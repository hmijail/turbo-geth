package stateless

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ledgerwatch/turbo-geth/core/vm/stack"
	"math/big"
	"os"
	"os/signal"
	"runtime"
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
	Pc       		uint64
	Op       		string
	StackTop 		*stack.Stack
	MaxStack 		int
	Fault    		bool
	Depth 			int
}

type tx struct {
	TxHash          string
	Depth 			int
	Create			bool
	ContractAddress common.Address
	From            common.Address
	To              common.Address
	Input 			[]byte
	Opcodes         []opcode
}

type opcodeTracer struct {
	Txs             	[]tx
	detail, summary   	*bufio.Writer
	c 					int
}

func (ot *opcodeTracer) CaptureStart(depth int, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	fmt.Fprintf(ot.summary, "%sStart from=%v to=%v d=%d \n", strings.Repeat("\t",depth), from.String(), to.String(),depth)
	ot.Txs = append(ot.Txs, tx{From: from, To: to,  Create: create, Input: input, Depth: depth})
	//ot.w.Flush()
	if depth == 0 {
		ot.c++
	}
	return nil
}

func min(a int, b int) int {
	if a<b {
		return a
	} else {
		return b
	}
}

func (ot *opcodeTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, st *stack.Stack, _ *stack.ReturnStack, rData []byte, contract *vm.Contract, depth int, err error) error {
	// go down the storage hierarchy, creating levels if they don't exist already

	currentTx := env.TxHash.String()

	/*	var lastHash string
	if l := len(ot.Txs); l == 0 {
		lastHash = ""
	} else {
		lastHash = ot.Txs[l-1].TxHash
	}
	if depth>1 { // depth starts at 1 in CaptureState
		currentTx = strconv.Itoa(depth) + "-" + currentTx
	}
	if lastHash != currentTx {
		ot.Txs = append(ot.Txs, tx{
			TxHash: 			currentTx,
			ContractAddress: 	*contract.CodeAddr,
			Opcodes:			make([]opcode,0,50),

		})
		fmt.Fprintf(ot.w, "%s%s", strings.Repeat("\t",depth), currentTx)
		if err != nil {
			fmt.Fprintf(ot.w, " e=%v", err.Error())
		}
		fmt.Fprintf(ot.w, "\n")
		ot.w.Flush()
	}*/

	l := len(ot.Txs)
	tracedTx := &ot.Txs[l-1]
	lastHash := &tracedTx.TxHash
	lastTxOpcodes := tracedTx.Opcodes
	lops := len(lastTxOpcodes)
	var lastOpDepth = 0
	if lops>0 {
		lastOpDepth = lastTxOpcodes[lops-1].Depth
	}

	if !((*lastHash == currentTx) && (lastOpDepth == depth)) {
		fmt.Fprintf(ot.summary, "%s%d-%s"/*\twas %d-%s\tsame? h=%v d=%v\n"*/,
			strings.Repeat("\t",depth), depth, currentTx/*, tracedTx.Depth+1, *lastHash,(*lastHash == currentTx),(tracedTx.Depth+1 == depth)*/)

		fmt.Fprintf(ot.summary, "\tpc=%x op=%s", pc, op.String())
		fmt.Fprintf(ot.summary, "\n")
		//if err != nil {
		//	fmt.Fprintf(ot.w, " e=%v", err.Error())
		//}
		//fmt.Fprintf(ot.w, "\n")
		//ot.w.Flush()
	}

	if *lastHash == "" {
		// entry was created by CaptureStart but is missing data
		*lastHash = currentTx
		tracedTx.ContractAddress = contract.Address()
		//fmt.Fprintf(ot.w, "%sFilled in TxHash\n", strings.Repeat("\t",depth))
	}

	stackTop := stack.New()
	// the most stack positions consumed by any opcode is 7
	for i:= min(7, st.Len()-1); i>0; i-- {
		stackTop.Push(st.Back(i))
	}

	tracedTx.Opcodes = append(tracedTx.Opcodes, opcode{pc, op.String(), stackTop, st.Len(), false, depth})

	//fmt.Printf("Tx  %s pc %x opcode %s", currentTx.String(), pc, op.String())

	return nil
}
func (ot *opcodeTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, rst *stack.ReturnStack, contract *vm.Contract, depth int, err error) error {
	ot.CaptureState(env, pc, op, gas, cost, memory, stack, rst, nil, contract, depth, err)

	l := len(ot.Txs)
	tracedTx := &ot.Txs[l-1]
	lastOpcode := len(tracedTx.Opcodes)
	tracedTx.Opcodes[lastOpcode].Fault = true

	currentTx := env.TxHash.String()

	fmt.Fprintf(ot.summary, "FAULT %s err=%v\n", strings.Repeat("\t",depth), err.Error())
	fmt.Printf("FAULT %s tx=%s err=%v\n", strings.Repeat("\t",depth), currentTx, err.Error())

	//t.summary.Flush()
	return nil
}
func (ot *opcodeTracer) CaptureEnd(depth int, output []byte, gasUsed uint64, t time.Duration, err error) error {
	fmt.Fprintf(ot.summary, "%sEnd d=%v", strings.Repeat("\t",depth), depth)
	if err != nil {
		fmt.Fprintf(ot.summary, " e=%v", err.Error())
	}
	fmt.Fprintf(ot.summary, "\n")
	//ot.summary.Flush()

	l := len(ot.Txs)
	tracedTx := &ot.Txs[l-1]
	if tracedTx.TxHash == "" {
		fmt.Printf("Dumping value tx from %s\n", tracedTx.From.String())
		fmt.Fprintf(ot.summary,"%sDumping value tx from %s\n", strings.Repeat("\t",depth), tracedTx.From.String())
		// if the Hash wasn't filled in by CaptureState, it means that it was a value transfer, for which we're not interested
		// so we remove the record
		ot.Txs = ot.Txs[:l-1]
	}

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
func CheckChangeSets(genesis *core.Genesis, blockNum uint64, chaindata string, historyfile string, nocheck bool, writeReceipts bool, numBlocks uint64) error {
	blockNumOrig := blockNum
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

	ot := new(opcodeTracer)//NewOpcodeTracer()

	f, err := os.OpenFile("./opcodes.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	check(err)
	defer f.Close()
	ot.detail = bufio.NewWriter(f)
	defer ot.detail.Flush()

	f2, err := os.OpenFile("./summary", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	check(err)
	defer f2.Close()
	ot.summary = bufio.NewWriter(f2)
	defer ot.summary.Flush()

	chainDb := ethdb.MustOpen(chaindata)
	defer chainDb.Close()
	historyDb := chainDb
	if chaindata != historyfile {
		historyDb = ethdb.MustOpen(historyfile)
	}
	historyTx, err1 := historyDb.KV().Begin(context.Background(), nil, false)
	if err1 != nil {
		return err1
	}
	defer historyTx.Rollback()
	chainConfig := genesis.Config
	engine := ethash.NewFaker()
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
	defer batch.Rollback()
	for !interrupt {
		block := bc.GetBlockByNumber(blockNum)
		if block == nil {
			break
		}

		dbstate := state.NewPlainDBState(historyTx, block.NumberU64()-1)
		intraBlockState := state.New(dbstate)
		intraBlockState.SetTracer(ot)
		csw := state.NewChangeSetWriterPlain(block.NumberU64() - 1)
		var blockWriter state.StateWriter
		if nocheck {
			blockWriter = noOpWriter
		} else {
			blockWriter = csw
		}

		receipts, err1 := runBlock(intraBlockState, noOpWriter, blockWriter, chainConfig, bc, block, vmConfig)
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
			if batch.BatchSize() >= batch.IdealBatchSize() {
				log.Info("Committing receipts", "up to block", block.NumberU64(), "batch size", common.StorageSize(batch.BatchSize()))
				if err := batch.CommitAndBegin(context.Background()); err != nil {
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

			dbAccountChanges, err := ethdb.GetChangeSetByBlock(historyDb, false /* storage */, blockNum)
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

			dbStorageChanges, err := ethdb.GetChangeSetByBlock(historyDb, true /* storage */, blockNum)
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

		m := make(map[uint64][]tx)
		m[block.Number().Uint64()] = ot.Txs
		json, err := json.MarshalIndent(m, "", fmt.Sprintf("\t"))
		if err != nil {
			log.Error(err.Error())
		}
		ot.detail.Write(json)


		numOpcodes := 0
		for _ , t := range ot.Txs {
			depthPrefix := ""
			if t.Depth > 0 {
				depthPrefix = fmt.Sprintf("%d-", t.Depth)
			}
			fmt.Fprintf(ot.summary, "tx %s%s\n", depthPrefix, t.TxHash)
			for _ , o := range t.Opcodes {
				fmt.Fprintf(ot.summary, "\t%x\t%-20s", o.Pc, o.Op)
				if o.StackTop.Len()>0 {
					fmt.Fprintf(ot.summary, "\t%d:", o.MaxStack)
				}
				for i := 0; i < o.StackTop.Len(); i++ {
					fmt.Fprintf(ot.summary, "%x ", o.StackTop.Back(i))
				}
				fmt.Fprint(ot.summary, "\n")
			}
			numOpcodes += len(t.Opcodes)
		}
		//fmt.Printf("Block %d : %d toplevel txs, %d txs, %d opcodes\n", blockNum, ot.c, len(ot.Txs), numOpcodes)
		ot.Txs = nil
		//ot.counterNonCalls = 0
		//ot.counterCalls = 0

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

		if blockNum>blockNumOrig + numBlocks {
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
