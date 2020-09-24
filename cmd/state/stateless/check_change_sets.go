package stateless

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/ledgerwatch/turbo-geth/core/vm/stack"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/changeset"
	"github.com/ledgerwatch/turbo-geth/consensus/ethash"
	"github.com/ledgerwatch/turbo-geth/core"
	"github.com/ledgerwatch/turbo-geth/core/rawdb"
	"github.com/ledgerwatch/turbo-geth/core/state"
	"github.com/ledgerwatch/turbo-geth/core/types"
	"github.com/ledgerwatch/turbo-geth/core/vm"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/log"
)

type opcode struct {
	pc uint64
	op vm.OpCode
	stackTop *stack.Stack
}

type txOpcodes struct {
	txHash string
	contractAddress common.Address
	opcodes []opcode
}

type opcodeTracer struct {
	txs []txOpcodes
	counter int
}

func (ot *opcodeTracer) CaptureStart(depth int, from common.Address, to common.Address, call bool, input []byte, gas uint64, value *big.Int) error {
	//fmt.Printf("from %s", from.String())
	ot.counter ++
	return nil
}
func (ot *opcodeTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, st *stack.Stack, _ *stack.ReturnStack, contract *vm.Contract, depth int, err error) error {
	// go down the storage hierarchy, creating levels if they don't exist already
	var lastTx string
	if l := len(ot.txs); l == 0 {
		lastTx = ""
	} else {
		lastTx = ot.txs[l-1].txHash
	}
	currentTx := env.TxHash.String()
	if depth>1 {
		currentTx += "-" + strconv.Itoa(depth)
	}
	if lastTx != currentTx {
		ot.txs = append(ot.txs, txOpcodes{currentTx, *contract.CodeAddr, make([]opcode,0,10)})
	}

	tracedTx := &ot.txs[len(ot.txs)-1]
	//opcodes := &tracedTx.opcodes
	stackTop := stack.New(7)
	copy(stackTop.Data, st.Data)

	tracedTx.opcodes = append(tracedTx.opcodes, opcode{pc, op, stackTop})

	//fmt.Printf("Tx  %s pc %x opcode %s", currentTx.String(), pc, op.String())

	return nil
}
func (ot *opcodeTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, _ *stack.ReturnStack, contract *vm.Contract, depth int, err error) error {
	return nil
}
func (ot *opcodeTracer) CaptureEnd(depth int, output []byte, gasUsed uint64, t time.Duration, err error) error {
	return nil
}
func (ot *opcodeTracer) CaptureCreate(creator common.Address, creation common.Address) error {
	return nil
}
func (ot *opcodeTracer) CaptureAccountRead(account common.Address) error {
	return nil
}
func (ot *opcodeTracer) CaptureAccountWrite(account common.Address) error {
	return nil
}

func NewOpcodeTracer() *opcodeTracer {
	return &opcodeTracer{}
}

// CheckChangeSets re-executes historical transactions in read-only mode
// and checks that their outputs match the database ChangeSets.
func CheckChangeSets(genesis *core.Genesis, blockNum uint64, chaindata string, historyfile string, nocheck bool, writeReceipts bool) error {
	if len(historyfile) == 0 {
		historyfile = chaindata
	}

	startTime := time.Now()
	sigs := make(chan os.Signal, 1)
	interruptCh := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		interruptCh <- true
	}()

	f, err := os.OpenFile("./opcodes", os.O_WRONLY|os.O_CREATE, 0600)
	check(err)
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	chainDb := ethdb.MustOpen(chaindata)
	defer chainDb.Close()
	historyDb := chainDb
	if chaindata != historyfile {
		historyDb = ethdb.MustOpen(historyfile)
	}

	chainConfig := genesis.Config
	engine := ethash.NewFaker()
	ot := NewOpcodeTracer()
	vmConfig := vm.Config{Tracer: ot, Debug: true}
	txCacher := core.NewTxSenderCacher(runtime.NumCPU())
	bc, err := core.NewBlockChain(chainDb, nil, chainConfig, engine, vmConfig, nil, txCacher)
	if err != nil {
		return err
	}
	defer bc.Stop()

	noOpWriter := state.NewNoopWriter()

	interrupt := false
	batch := chainDb.NewBatch()
	for !interrupt {
		block := bc.GetBlockByNumber(blockNum)
		if block == nil {
			break
		}

		dbstate := state.NewPlainDBState(historyDb.KV(), block.NumberU64()-1)
		intraBlockState := state.New(dbstate)
		intraBlockState.SetTracer(ot)
		csw := state.NewChangeSetWriterPlain(block.NumberU64() - 1)
		var blockWriter state.StateWriter
		if nocheck {
			blockWriter = noOpWriter
		} else {
			blockWriter = csw
		}

		receipts, err1 := runBlock(intraBlockState, noOpWriter, blockWriter, chainConfig, bc, block)
		if err1 != nil {
			return err1
		}
		if chainConfig.IsByzantium(block.Number()) {
			receiptSha := types.DeriveSha(receipts)
			if receiptSha != block.Header().ReceiptHash {
				return fmt.Errorf("mismatched receipt headers for block %d", block.NumberU64())
			}
		}
		if writeReceipts {
			rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), receipts)
			if batch.BatchSize() >= chainDb.IdealBatchSize() {
				log.Info("Committing receipts", "up to block", block.NumberU64(), "batch size", common.StorageSize(batch.BatchSize()))
				if _, err := batch.Commit(); err != nil {
					return err
				}
			}
		}

		if !nocheck {
			accountChanges, err := csw.GetAccountChanges()
			if err != nil {
				return err
			}
			var expectedAccountChanges []byte
			expectedAccountChanges, err = changeset.EncodeAccountsPlain(accountChanges)
			if err != nil {
				return err
			}

			dbAccountChanges, err := historyDb.GetChangeSetByBlock(false /* storage */, blockNum)
			if err != nil {
				return err
			}

			if !bytes.Equal(dbAccountChanges, expectedAccountChanges) {
				fmt.Printf("Unexpected account changes in block %d\nIn the database: ======================\n", blockNum)
				if err = changeset.AccountChangeSetPlainBytes(dbAccountChanges).Walk(func(k, v []byte) error {
					fmt.Printf("0x%x: %x\n", k, v)
					return nil
				}); err != nil {
					return err
				}
				fmt.Printf("Expected: ==========================\n")
				if err = changeset.AccountChangeSetPlainBytes(expectedAccountChanges).Walk(func(k, v []byte) error {
					fmt.Printf("0x%x %x\n", k, v)
					return nil
				}); err != nil {
					return err
				}
				return nil
			}

			expectedStorageChanges, err := csw.GetStorageChanges()
			if err != nil {
				return err
			}
			expectedtorageSerialized := make([]byte, 0)
			if expectedStorageChanges.Len() > 0 {
				expectedtorageSerialized, err = changeset.EncodeStoragePlain(expectedStorageChanges)
				if err != nil {
					return err
				}
			}

			dbStorageChanges, err := historyDb.GetChangeSetByBlock(true /* storage */, blockNum)
			if err != nil {
				return err
			}
			equal := true
			if !bytes.Equal(dbStorageChanges, expectedtorageSerialized) {
				var addrs [][]byte
				var keys [][]byte
				var vals [][]byte
				if err = changeset.StorageChangeSetPlainBytes(dbStorageChanges).Walk(func(k, v []byte) error {
					addrs = append(addrs, common.CopyBytes(k[:common.AddressLength]))
					keys = append(keys, common.CopyBytes(k[common.AddressLength+common.IncarnationLength:]))
					vals = append(vals, common.CopyBytes(v))
					return nil
				}); err != nil {
					return err
				}
				i := 0
				if err = changeset.StorageChangeSetPlainBytes(expectedtorageSerialized).Walk(func(k, v []byte) error {
					if !equal {
						return nil
					}
					if i >= len(addrs) {
						equal = false
						return nil
					}
					if !bytes.Equal(k[:common.AddressLength], addrs[i]) {
						equal = false
						return nil
					}
					if !bytes.Equal(k[common.AddressLength+common.IncarnationLength:], keys[i]) {
						equal = false
						return nil
					}
					if !bytes.Equal(v, vals[i]) {
						equal = false
						return nil
					}
					i++
					return nil
				}); err != nil {
					return err
				}
			}
			if !equal {
				fmt.Printf("Unexpected storage changes in block %d\nIn the database: ======================\n", blockNum)
				if err = changeset.StorageChangeSetPlainBytes(dbStorageChanges).Walk(func(k, v []byte) error {
					fmt.Printf("0x%x: [%x]\n", k, v)
					return nil
				}); err != nil {
					return err
				}
				fmt.Printf("Expected: ==========================\n")
				if err = changeset.StorageChangeSetPlainBytes(expectedtorageSerialized).Walk(func(k, v []byte) error {
					fmt.Printf("0x%x: [%x]\n", k, v)
					return nil
				}); err != nil {
					return err
				}
				return nil
			}
		}

		numOpcodes := 0
		for _ , t := range ot.txs {
			fmt.Fprintf(w, "tx %x\n", t.txHash)
			for _ , o := range t.opcodes {
				fmt.Fprintf(w, "\t%x\t%x\t%s\t", o.pc, o.op, o.op.String())
				if l := len(o.stackTop.Data); l > 0 {
					fmt.Fprintf(w, "%d : ", l)
				}
				for i := range o.stackTop.Data {
					fmt.Fprintf(w, "%s ", o.stackTop.Data[i].String())
				}
				fmt.Fprint(w, "\n")
			}
			numOpcodes += len(t.opcodes)
			// remove used elements?
		}
		fmt.Printf("Block %d : %d txs, %d opcodes, counter = %d \n", blockNum, len(ot.txs), numOpcodes, ot.counter)
		ot.txs = nil

		blockNum++
		if blockNum%1000 == 0 {
			log.Info("Checked", "blocks", blockNum)
		}

		// Check for interrupts
		select {
		case interrupt = <-interruptCh:
			fmt.Println("interrupted, please wait for cleanup...")
		default:
		}

		if blockNum>9000000 {
			interrupt = true
		}
	}
	if writeReceipts {
		log.Info("Committing final receipts", "batch size", common.StorageSize(batch.BatchSize()))
		if _, err := batch.Commit(); err != nil {
			return err
		}
	}
	log.Info("Checked", "blocks", blockNum, "next time specify --block", blockNum, "duration", time.Since(startTime))
	return nil
}
