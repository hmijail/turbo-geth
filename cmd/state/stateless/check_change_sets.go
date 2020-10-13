package stateless

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/changeset"
	"github.com/ledgerwatch/turbo-geth/consensus/ethash"
	"github.com/ledgerwatch/turbo-geth/core"
	"github.com/ledgerwatch/turbo-geth/core/rawdb"
	"github.com/ledgerwatch/turbo-geth/core/state"
	"github.com/ledgerwatch/turbo-geth/core/types"
	"github.com/ledgerwatch/turbo-geth/core/vm"
	"github.com/ledgerwatch/turbo-geth/core/vm/stack"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/log"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type opcode struct {
	Pc       		Uint64AsHex
	Op       		string
	StackTop 		*stack.Stack
	//StackTop 		[]uint256.Int
	RetStackTop		[]uint32
	MaxStack 		int
	MaxRStack 		int
	Fault    		bool
	//Depth 			int
}

type tx struct {
	TxHash          string
	Depth 			int
	Create			bool
	ContractAddress common.Address
	From            common.Address
	To              common.Address
	Input 			ByteSliceAsHex
	Opcodes         []opcode
}

type opcodeTracer struct {
	Txs             	[]*tx
	detail, summary   	*bufio.Writer
	c 					int
	stack 				[]*tx
	stackIndexes		[]int
	showNext			bool
	lastLine			string
}

type ByteSliceAsHex struct {
	ByteSlice	[]byte
}

func (bs ByteSliceAsHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%x", bs.ByteSlice))
}

type Uint64AsHex struct {
	uint64
}

func (ui Uint64AsHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%x", ui.uint64))
}

func min(a int, b int) int {
	if a<b {
		return a
	} else {
		return b
	}
}

func (ot *opcodeTracer) CaptureStart(depth int, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	fmt.Fprint(ot.summary, ot.lastLine)
	fmt.Fprintf(ot.summary, "%sStart from=%v to=%v d=%d \n", strings.Repeat("\t",depth), from.String(), to.String(),depth)

	// When a CaptureStart is called, a Tx is starting. Create its entry in our list and initialize it with the partial data available
	newTx := tx{From: from, To: to,  Create: create, Input: ByteSliceAsHex{input}, Depth: depth}
	ot.Txs = append(ot.Txs, &newTx)

	// take note in our own stack that the tx stack has grown
	ot.stack = append(ot.stack, &newTx)

	ot.showNext = true
	return nil
}

func (ot *opcodeTracer) CaptureEnd(depth int, output []byte, gasUsed uint64, t time.Duration, err error) error {
	//lt := len(ot.Txs)
	//lastEntry := &ot.Txs[lt-1]

	// When a CaptureEnd is called, a Tx has finished. Pop our stack
	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]
	//sanity check: the last entry in our stack should be the last entry in the list of txs
	//lse := ot.stack[ls-1]
	//if lse != lastEntry {
	//	panic(fmt.Sprintf("End of tx: last item of stack should be == last item of list of txs, but isn't\n" +
	//		"last in stack:\ttx=%d-%s ops=%d from=%s\n" +
	//		"last in list:\ttx=%d-%s ops=%d from=%s\n",
	//		lse.Depth, lse.TxHash, len(lse.Opcodes), lse.From,
	//		lastEntry.Depth, lastEntry.TxHash, len(lastEntry.Opcodes), lastEntry.From))
	//}
	ot.stack = ot.stack[ : ls-1]

	fmt.Fprint(ot.summary, ot.lastLine)
	ot.lastLine = ""

	//sanity check
	if depth != currentEntry.Depth {
		panic(fmt.Sprintf("End of tx at depth=%d, but trace entry's depth=%d", depth, currentEntry.Depth))
	}



	fmt.Fprintf(ot.summary, "%sEnd d=%v ops=%d", strings.Repeat("\t",depth), depth, len(currentEntry.Opcodes))
	if err != nil {
		fmt.Fprintf(ot.summary, " e=%v", err.Error())
	}
	fmt.Fprintf(ot.summary, "\n")
	//ot.summary.Flush()



	//if the finished transaction was only a value transfer (no opcodes), then we're not interested in it. Remove it from our list.
	// if there were opcodes, the entry would have been fully init'ed, and so it would have a TxHash
	// also, a tx without opcodes can't have subordinate txs
	if currentEntry.TxHash == "" {
		fmt.Printf("Dumping value tx from %s\n", currentEntry.From.String())
		fmt.Fprintf(ot.summary,"%sDumping value tx from %s\n", strings.Repeat("\t",depth), currentEntry.From.String())
		lt := len(ot.Txs)
		ot.Txs = ot.Txs[:lt-1]
	}

	ot.showNext = true
	return nil
}

func (ot *opcodeTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, st *stack.Stack, retst *stack.ReturnStack, rData []byte, contract *vm.Contract, opDepth int, err error) error {

	currentTxHash := env.TxHash.String()
	currentTxDepth := opDepth - 1

	//l := len(ot.Txs)
	//lastTxEntry := &ot.Txs[l-1]
	//lastEntryHash := &lastTxEntry.TxHash

	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]

	//sanity check
	if currentEntry.Depth != currentTxDepth {
		panic(fmt.Sprintf("Depth should be the same but isn't: current tx's %d, current entry's %d", currentTxDepth, currentEntry.Depth))
	}

	// prepare the opcode's stack for saving
	stackTop := stack.New()
	// the most stack positions consumed by any opcode is 7
	for i:= min(7, st.Len()-1); i>=0; i-- {
		stackTop.Push(st.Back(i))
	}
	//stackTop := make([]uint256.Int, 7)
	//copy(stackTop, st.Data)

	lrs := len(retst.Data())
	retStackTop := make([]uint32, lrs)
	copy(retStackTop, retst.Data())



	// is the Tx entry still not fully initialized?
	if currentEntry.TxHash == "" {
		// CaptureStart creates the entry for a new Tx, but doesn't have access to EVM data, like the Tx Hash
		// here we assume that the tx entry was recently created by CaptureStart
		// AND this is the first CaptureState that has happened since then
		// AND that both Captures are for the same transaction
		// AND that we can't go into another depth without executing at least 1 opcode
		// Note that the only connection between both that we can notice is that the current op's depth should be lastTxEntry.Depth+1

		// fill in the missing data in the entry
		currentEntry.TxHash = currentTxHash
		currentEntry.ContractAddress = contract.Address()
		//fmt.Fprintf(ot.w, "%sFilled in TxHash\n", strings.Repeat("\t",depth))
	}

	//cases:
	// same tx hash, same depth
	// same tx hash, different depth
	// different hash, startDepth ==0

	line := fmt.Sprintf("%s%d-%s", strings.Repeat("\t", currentTxDepth), currentTxDepth, currentTxHash )
	line += fmt.Sprintf("\tpc=%x op=%s ops=%d", pc, op.String(), len(currentEntry.Opcodes))
	if err != nil {
		line += fmt.Sprintf(" ---- e=%v", err.Error())
	}
	line += fmt.Sprintf("\n")

	if ot.showNext {
		fmt.Fprintf(ot.summary, line)
		ot.showNext = false
	}

	ot.lastLine = line
/*
	// if there is any hint that the current op is in a different transaction, print something
	if !((currentEntry.TxHash == currentTxHash) && (lastTxEntry.Depth == currentTxDepth)) {
		// they can never change at the same time. Either we're at depth 0 and then TxHash can change between calls;
		// or we're at depth >0 and then the TxHash is fixed

		fmt.Fprintf(ot.summary, "%s%d-%s",
			strings.Repeat("\t", currentTxDepth), currentTxDepth, currentTxHash )

		fmt.Fprintf(ot.summary, "\tpc=%x op=%s", pc, op.String())
		if err != nil {
			fmt.Fprintf(ot.summary, " ---- e=%v", err.Error())
		}

		fmt.Fprintf(ot.summary, "\n")
	}


	// check the assumption that depth and txHash don't change at the same time
	if (*lastEntryHash != currentTxHash) && (lastTxEntry.Depth != currentTxDepth) && (currentTxDepth != 0) {
		panic("Both hash and depth changed at once")
	}

	// beginning and end of Txs get a CaptureStart and CaptureEnd call, so they are easy to track. But there is no explicit capture func for a returning tx
	// here we need to
	// decide to which transaction does the opcode belong, and do the related bookkeeping
	if (*lastEntryHash == currentTxHash) {
		//adjust our stack if the depth has changed
		switch {
		case lastTxEntry.Depth == currentTxDepth:
			// default case, already dealt with

		case lastTxEntry.Depth < currentTxDepth:
			// this case can't be detected like this, because CaptureStart was needed to create the last entry in our stack, and that entry has the right depth.
			// we leave the case here for clarity. The actual processing is the case lastEntryHash == ""


		case lastTxEntry.Depth > currentTxDepth:
			// the tx call stack was just popped. Find the existing Tx record that corresponds to the current Opcode.
			fmt.Fprintf(ot.summary, "%sPop from d=%d to d=%d\n",strings.Repeat("\t", currentTxDepth), lastTxEntry.Depth, currentTxDepth)
			l := len(ot.stack)
			// the last element of our stack is the tx that has finished. We want the previous element.
			currentEntry = ot.stack[l-1]
			//sanity check
			if currentTxHash != currentEntry.TxHash || currentTxDepth != currentEntry.Depth {
				panic(fmt.Sprintf("Tried returning to previous Tx, but hash is different\n" +
					"Current  \td=%d,h=%s\n" +
					"Recovered\td=%d,h=%s\n", currentTxDepth, currentTxHash, currentEntry.Depth, currentEntry.TxHash))
			}
		}
	} else {
		// it's a different tx
		if currentTxDepth != 0 {
			panic(fmt.Sprintf("Changing Tx while in depth = %d\nOldTx = %x\nNewTx = %x\n", currentTxDepth, lastEntryHash, currentTxHash))
		}
		// since it's a different tx, this must be the first opcode for this tx. assert it, and store the tx in our stack
		if len(ot.stack) != 0 {
			panic(fmt.Sprintf("Changed Tx but stack is not empty: last Tx = %x", lastEntryHash))
		}
		ot.stack = append(ot.stack, lastTxEntry)
		currentEntry = lastTxEntry
	}
*/

	//store the opcode and its related data
	currentEntry.Opcodes = append(
		currentEntry.Opcodes,
		opcode{Uint64AsHex{pc}, op.String(), stackTop, retStackTop, st.Len(), lrs, false},
	)

	//fmt.Printf("Tx  %s pc %x opcode %s", currentTxHash.String(), pc, op.String())

	return nil
}
func (ot *opcodeTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, rst *stack.ReturnStack, contract *vm.Contract, depth int, err error) error {
	ot.CaptureState(env, pc, op, gas, cost, memory, stack, rst, nil, contract, depth, err)

	//l := len(ot.Txs)
	//tracedTx := &ot.Txs[l-1]
	//lastOpcode := len(*tracedTx.Opcodes)
	//tracedTx.Opcodes[lastOpcode].Fault = true

	currentTx := env.TxHash.String()

	fmt.Fprintf(ot.summary, "FAULT %s err=%v\n", strings.Repeat("\t",depth), err.Error())
	fmt.Printf("FAULT %s tx=%s err=%v\n", strings.Repeat("\t",depth), currentTx, err.Error())

	//t.summary.Flush()
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

		m := make(map[uint64][]*tx)
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
			fmt.Fprintf(ot.summary, "tx %s%s  input=%x\n", depthPrefix, t.TxHash, t.Input)
			for i , o := range t.Opcodes {
				fmt.Fprintf(ot.summary, "%d\t%x\t%-20s", i, o.Pc.uint64, o.Op)
				if l := o.StackTop.Len(); l>0 {
					fmt.Fprintf(ot.summary, "\t%d:", o.MaxStack)
					for i := 0; i < l; i++ {
						fmt.Fprintf(ot.summary, "%x ", o.StackTop.Back(i))
					}
				}
				if o.MaxRStack > 0 {
					fmt.Fprintf(ot.summary, "\t\trs:%d:", o.MaxRStack)
					for i := 0; i < o.MaxRStack; i++ {
						fmt.Fprintf(ot.summary, "%x ", o.RetStackTop[i])
					}
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
