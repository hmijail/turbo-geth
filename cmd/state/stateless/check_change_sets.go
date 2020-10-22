package stateless

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
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
	"strconv"
	"syscall"
	"time"
)

//const MaxUint = ^uint(0)
//const MaxUint64 = ^uint64(0)
const MaxUint16 = ^uint16(0)

type opcode struct {
	Pc       		uint16
	Op       		vm.OpCode
	//StackTop 		*stack.Stack
	//StackTop 		[]uint256.Int
	//RetStackTop		RetStackTop
	//MaxStack 		int
	//MaxRStack 		int
	Fault    		string
	//Depth 			int
}

type	RetStackTop	[]uint32

type tx struct {
	TxHash          *common.Hash
	Depth 			int
	TxAddr			string
	CodeHash 		*common.Hash
	From            common.Address
	To              common.Address
	Input 			sliceBytes //ByteSliceAsHex
	Segments 		sliceSegment
	Create			bool
	Fault 			string		//a fault set by CaptureEnd
	OpcodeFault		string		//a fault set by CaptureState
	Opcodes         sliceOpcodes
	//lastOpWasPush 		bool
	lastPc16   			uint16
	lastOp				vm.OpCode// = 0xfe // op INVALID
}

// types for slices are necessary for easyjson's generated un/marshalers
type sliceBytes 		[]byte
type sliceOpcodes		[]opcode
type sliceSegment		[]segment
type sliceSegmentDump 	[]segmentDump
//easyjson:json
type slicePtrTx			[]*tx

type opcodeTracer struct {
	Txs             	slicePtrTx
	fsumWriter			*bufio.Writer
	stack 				slicePtrTx
	//stackIndexes		[]int
	//showNext			bool
	//lastLine			string
	txsInDepth			[]int16

	//SegmentDumps 		sliceSegmentDump
	saveOpcodes			bool
	saveSegments		bool
	blockNumber 		uint64
}


func NewOpcodeTracer(blockNum uint64, saveOpcodes bool, saveSegments bool) *opcodeTracer {
	res := new(opcodeTracer)
	res.txsInDepth = make([]int16,1,4)
	res.stack = make([]*tx, 0, 8)
	res.Txs = make([]*tx, 0, 50)
	res.saveOpcodes = saveOpcodes
	res.saveSegments = saveSegments
	res.blockNumber = blockNum
	return res
}

//type ByteSliceAsHex struct {
//	ByteSlice	[]byte
//}
//
//func (bs ByteSliceAsHex) MarshalJSON() ([]byte, error) {
//	return json.Marshal(fmt.Sprintf("%x", bs.ByteSlice))
//}


func min(a int, b int) int {
	if a<b {
		return a
	} else {
		return b
	}
}

type segment struct {
	Start 	uint16
	End		uint16
}

type segmentDump struct {
	Tx			*common.Hash
	TxAddr		*string
	CodeHash	*common.Hash
	Segments 	*sliceSegment
	OpcodeFault *string
	Fault		*string
	Create 		bool
}


/*type blockSegments struct {
	BlockNum uint64
	Segments []segmentDump
}*/

type blockTxs struct {
	BlockNum	*uint64
	Txs 		*slicePtrTx
}

func (ot *opcodeTracer) CaptureStart(depth int, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	//fmt.Fprint(ot.summary, ot.lastLine)

	// When a CaptureStart is called, a Tx is starting. Create its entry in our list and initialize it with the partial data available
	//calculate the "address" of the Tx in its tree
	ltid := len(ot.txsInDepth)
	if ltid-1 != depth {
		panic(fmt.Sprintf("Wrong addr slice depth: d=%d, slice len=%d", depth, ltid))
	}
	//if depth > ltid-1  {
	//	ot.txsInDepth = append(ot.txsInDepth, 0)
	//}
	ot.txsInDepth[depth]++
	ot.txsInDepth = append(ot.txsInDepth, 0)

	ls := len(ot.stack)
	txAddr := ""
	if ls>0 {
		txAddr = ot.stack[ls-1].TxAddr + "-" + strconv.Itoa(int(ot.txsInDepth[depth]))// fmt.Sprintf("%s-%d", ot.stack[ls-1].TxAddr, ot.txsInDepth[depth])
	} else {
		txAddr = strconv.Itoa(int(ot.txsInDepth[depth]))
	}

	//newSegs := make(sliceSegment, 0, 8)
	newTx := tx{From: from, To: to,  Create: create, Input: input, Depth: depth, TxAddr: txAddr, lastOp: 0xfe, lastPc16: MaxUint16}
	ot.Txs = append(ot.Txs, &newTx)

	// take note in our own stack that the tx stack has grown
	//ltxs := len(ot.Txs)
	ot.stack = append(ot.stack, &newTx)
	//newSeg := segmentDump{
	//	TxAddr:   txAddr,
	//	Segments: &newSegs,
	//}
	//ot.SegmentDumps = append(ot.SegmentDumps, newSeg)

	//ot.showNext = true

	//fmt.Fprintf(ot.summary, "%sStart addr=%s from=%v to=%v d=%d \n", strings.Repeat("\t",depth), txAddr, from.String(), to.String(),depth)

	return nil
}

func (ot *opcodeTracer) CaptureEnd(depth int, output []byte, gasUsed uint64, t time.Duration, err error) error {
	//lt := len(ot.Txs)
	//lastEntry := &ot.Txs[lt-1]

	// When a CaptureEnd is called, a Tx has finished. Pop our stack
	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]
	ot.stack = ot.stack[ : ls-1]
	ot.txsInDepth = ot.txsInDepth[:depth+1]

	// sanity check: depth of stack == depth reported by system
	if ls-1 != depth || depth != currentEntry.Depth {
		panic(fmt.Sprintf("End of Tx at d=%d but stack has d=%d and entry has d=%", depth, ls, currentEntry.Depth))
	}

	// Close the last segment
	if ot.saveSegments {
		lseg := len(currentEntry.Segments)
		if lseg>0 {
			cee := currentEntry.Segments[lseg-1].End
			if cee != 0 && cee != currentEntry.lastPc16 {
				panic(fmt.Sprintf("CaptureEnd wanted to close last segment with %d but already contains %d", currentEntry.lastPc16, cee))
			}
			currentEntry.Segments[lseg-1].End = currentEntry.lastPc16
			//fmt.Fprintf(ot.fsumWriter,"Segment %d ends\n", lseg)
		}
	}


	errstr := ""
	if err != nil {
		errstr = err.Error()
		currentEntry.Fault = errstr
	}
	//if currentEntry.OpcodeFault != errstr {
	//	// This happens (for example) with Out-Of-Gas faults
	//	fmt.Fprintf(ot.fsumWriter, "CaptureEnd FAULT different to opcode's. opFault=%s, txFault=%s, txaddr=%s tx=%v\n",
	//		currentEntry.OpcodeFault, errstr, currentEntry.TxAddr, currentEntry.TxHash)
	//}


	//fmt.Fprint(ot.summary, ot.lastLine)
	//ot.lastLine = ""

	//ot.showNext = true
	return nil
}

func (ot *opcodeTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, st *stack.Stack, retst *stack.ReturnStack, rData []byte, contract *vm.Contract, opDepth int, err error) error {
	//CaptureState sees the system as it is before the opcode is run. It seems to never get an error.

	//sanity check
	if pc > uint64(MaxUint16) {
		panic(fmt.Sprintf("PC is bigger than uint16! pc=%d=0x%x", pc, pc))
	}

	pc16 := uint16(pc)
	currentTxHash := env.TxHash
	currentTxDepth := opDepth - 1

	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]

	//sanity check
	if currentEntry.Depth != currentTxDepth {
		panic(fmt.Sprintf("Depth should be the same but isn't: current tx's %d, current entry's %d", currentTxDepth, currentEntry.Depth))
	}

	// is the Tx entry still not fully initialized?
	if currentEntry.TxHash == nil {
		// CaptureStart creates the entry for a new Tx, but doesn't have access to EVM data, like the Tx Hash
		// here we assume that the tx entry was recently created by CaptureStart
		// AND this is the first CaptureState that has happened since then
		// AND that both Captures are for the same transaction
		// AND that we can't go into another depth without executing at least 1 opcode
		// Note that the only connection between CaptureStart and CaptureState that we can notice is that the current op's depth should be lastTxEntry.Depth+1

		// fill in the missing data in the entry
		currentEntry.TxHash = new(common.Hash)
		currentEntry.TxHash.SetBytes(currentTxHash.Bytes())
		currentEntry.CodeHash = new(common.Hash)
		currentEntry.CodeHash.SetBytes(contract.CodeHash.Bytes())
		if ot.saveOpcodes {
			currentEntry.Opcodes = make([]opcode, 0, 200)
		}
		//fmt.Fprintf(ot.w, "%sFilled in TxHash\n", strings.Repeat("\t",depth))

		if ot.saveSegments{
			currentEntry.Segments = make(sliceSegment, 0, 10)
		}
	}


	// prepare the opcode's stack for saving
	//stackTop := &stack.Stack{Data: make([]uint256.Int, 0, 7)}//stack.New()
	// the most stack positions consumed by any opcode is 7
	//for i:= min(7, st.Len()-1); i>=0; i-- {
	//	stackTop.Push(st.Back(i))
	//}
	//THIS VERSION SHOULD BE FASTER BUT IS UNTESTED
	//stackTop := make([]uint256.Int, 7, 7)
	//sl := st.Len()
	//minl := min(7, sl)
	//startcopy := sl-minl
	//stackTop := &stack.Stack{Data: make([]uint256.Int, minl, minl)}//stack.New()
	//copy(stackTop.Data, st.Data[startcopy:sl])

	// deal with the RStack - is it used at all??
	lrs := len(retst.Data())
	var retStackTop []uint32
	if lrs>0 {
		fmt.Fprintf(ot.fsumWriter,"RStack used in b=%d, tx=%s, txaddr=%s", ot.blockNumber, currentEntry.TxHash, currentEntry.TxAddr)
		//fmt.Printf("RStack used in b=%d, tx=%s, txaddr=%s", ot.blockNumber, currentEntry.TxHash, currentEntry.TxAddr)
		retStackTop = make([]uint32, lrs, lrs)
		copy(retStackTop, retst.Data())
	}

	//sanity check
	if currentEntry.OpcodeFault != "" {
		panic(fmt.Sprintf("Running opcodes but fault is already set. txFault=%s, opFault=%v, op=%s",
			currentEntry.OpcodeFault, err, op.String()))
	}

	// if it is a Fault, check whether we already have a record of the opcode. If so, just add the flag to it
	errstr := ""
	if err != nil {
		errstr = err.Error()
		currentEntry.OpcodeFault = errstr
	}


/*	line := fmt.Sprintf("%s%d-%s", strings.Repeat("\t", currentTxDepth), currentTxDepth, currentTxHash.String() )
	line += fmt.Sprintf("\tops=%d\tpc=%x\top=%s", len(currentEntry.Opcodes), pc, op.String())
	if errstr != "" {
		line += fmt.Sprintf(" ---- FAULT=%s\t", errstr)
	}
	//line += stackAsString(st)
	line += fmt.Sprintf("\n")
	ot.fsumWriter.WriteString(line)
	//ot.fsumWriter.Flush()
*/
	faultAndRepeated := false

	if pc16 == currentEntry.lastPc16 && op == currentEntry.lastOp {
		//it's a repeated opcode. We assume this only happens when it's a Fault.
		if err == nil {
			panic(fmt.Sprintf("Duplicate opcode with no fault. bn=%d txaddr=%s pc=%x op=%s",
				ot.blockNumber, currentEntry.TxAddr, pc, op.String()))
		}
		faultAndRepeated = true
		//ot.fsumWriter.WriteString("Fault for EXISTING opcode\n")
		//ot.fsumWriter.Flush()
		if ot.saveOpcodes {
			lo := len(currentEntry.Opcodes)
			currentEntry.Opcodes[lo-1].Fault = errstr
		}
	} else {
		// it's a new opcode
		if ot.saveOpcodes {
			newOpcode := opcode{pc16, op, errstr}
			currentEntry.Opcodes = append(currentEntry.Opcodes, newOpcode)
		}
	}


	// detect and store segments
	if ot.saveSegments {
		// PC discontinuities can only happen because of a PUSH (which is followed by the data to be pushed) or a JUMP (which lands into a JUMPDEST)
		// Therefore, after a PC discontinuity we either have op==JUMPDEST or lastOp==PUSH
		// Only the JUMPDEST case is a real control flow discontinuity and therefore starts a new segment

		lseg := len(currentEntry.Segments)
		isFirstSegment := lseg == 0
		isContinuous := pc16 == currentEntry.lastPc16+1 || currentEntry.lastOp.IsPush()
		if isFirstSegment || !isContinuous {
			// Record the end of the past segment, if there is one
			if !isFirstSegment {
				//fmt.Fprintf(ot.fsumWriter,"Segment %d ends\n", lseg)
				currentEntry.Segments[lseg-1].End = currentEntry.lastPc16
				//fmt.Printf("End\t%x\t%s\n", lastPc, lastOp.String())
			}
			// Start a new segment
			// Note that it can happen that a new segment starts with an opcode that triggers an Out Of Gas fault, so it'd be a segment with only 1 opcode (JUMPDEST)
			// The only case where we want to avoid creating a new segment is if the opcode is repeated, because then it was already in the previous segment
			if !faultAndRepeated {
				//fmt.Fprintf(ot.fsumWriter,"Segment %d begins\n", lseg+1)
				currentEntry.Segments = append(currentEntry.Segments, segment{Start: pc16})
				//fmt.Printf("Start\t%x\t%s\n", o.Pc.uint64, o.Op.String())

				//sanity check
				// we're starting a segment, so either we're in PC=0 or we have OP=JUMPDEST
				if pc16 != 0 && op.String() != "JUMPDEST" {
					panic(fmt.Sprintf("Bad segment? lastpc=%x, lastOp=%s; pc=%x, op=%s; bn=%d txaddr=%s tx=%d-%s",
						currentEntry.lastPc16, currentEntry.lastOp.String(), pc, op.String(), ot.blockNumber, currentEntry.TxAddr, currentEntry.Depth, currentEntry.TxHash.String()))
				}
			}
		}
	}

	//if ot.showNext {
	//	//fmt.Fprintf(ot.summary, line)
	//	ot.showNext = false
	//}
	//ot.lastLine = line

	currentEntry.lastPc16 = pc16
	//currentEntry.lastOpWasPush = op.IsPush()
	currentEntry.lastOp = op
	return nil
}

func (ot *opcodeTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, rst *stack.ReturnStack, contract *vm.Contract, opDepth int, err error) error {
	// CaptureFault sees the system as it is after the fault happens

	//currentTxHash := env.TxHash
	//currentTxDepth := opDepth - 1
	//fmt.Fprintf(ot.fsumWriter,"CaptureFault in tx=%d-%s\n", currentTxDepth, currentTxHash.String())

	// CaptureState might have already recorded the opcode before it failed. Call it again to make it flag that last opcode as failed
	ot.CaptureState(env, pc, op, gas, cost, memory, stack, rst, nil, contract, opDepth, err)

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

func stackAsString(st *stack.Stack) (str string) {
	//print the stack

	if l := st.Len(); l>0 {
		str = fmt.Sprintf("%d:", l)
		for i := 0; i < l; i++ {
			str+=fmt.Sprintf("%x ", st.Back(i))
		}
	}
	return str
}


// CheckChangeSets re-executes historical transactions in read-only mode
// and checks that their outputs match the database ChangeSets.
func CheckChangeSets(genesis *core.Genesis, blockNum uint64, chaindata string, historyfile string, nocheck bool,
	writeReceipts bool, numBlocks uint64, saveOpcodes bool, saveSegments bool) error {
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

	ot := NewOpcodeTracer(blockNum, saveOpcodes, saveSegments)

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
	//alreadyWrote := false

	var fops		*os.File
	var fopsWriter	*bufio.Writer
	var fopsEnc 	*gob.Encoder

	var fsum		*os.File
	//var fsumWriter	*bufio.Writer

	var fseg		*os.File
	var fsegWriter	*bufio.Writer
	var fsegEnc 	*gob.Encoder


	for !interrupt {
		block := bc.GetBlockByNumber(blockNum)
		if block == nil {
			break
		}

		bnStr := strconv.Itoa(int(blockNum))
		if saveOpcodes && fops == nil {
			fops, err = os.Create("./opcodes-"+bnStr)
			check(err)
			fopsWriter = bufio.NewWriter(fops)
			fopsEnc = gob.NewEncoder(fopsWriter)
		}

		if saveSegments && fseg == nil {
			fseg, err = os.Create("./segments-"+bnStr)
			check(err)
			fsegWriter = bufio.NewWriter(fseg)
			fsegEnc = gob.NewEncoder(fsegWriter)
		}

/*		if fsegJson == nil {
			fsegJson, err := os.Create("./segments-"+bnStr+".json")
			check(err)
			fsjWriter = bufio.NewWriter(fsegJson)
			fsjWriter.WriteString("{\n")
		}*/

		if fsum == nil {
			fsum, err = os.Create("./summary-"+bnStr)
			check(err)
			//defer fsum.Close()
			ot.fsumWriter = bufio.NewWriter(fsum)
			//defer summary.Flush()
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


		// go through the traces and act on them
		// To save the segments, we need a clear structure to later read the gob: blockNum, Num of txs, and for each tx save its data and segments
		if saveSegments {
			fsegEnc.Encode(blockNum)
			fsegEnc.Encode(len(ot.Txs))
		}
		for i := range ot.Txs {
			t := ot.Txs[i]

			if saveSegments {
				sd := segmentDump{t.TxHash, &t.TxAddr, t.CodeHash, &t.Segments, &t.OpcodeFault, &t.Fault, t.Create}
				fsegEnc.Encode(sd)
			}
			for j := range t.Opcodes {
				o := &t.Opcodes[j]
				//only print to the summary the opcodes that are interesting
				//isRStackUsed := o.MaxRStack != 0
				isOpFault := o.Fault != ""
				if isOpFault { // && !isRStackUsed {
					fmt.Fprintf(ot.fsumWriter, "Opcode FAULT\tb=%d taddr=%s TxF=%s opF=%s tx=%s\n", blockNum, t.TxAddr, t.Fault, t.OpcodeFault, t.TxHash.String())
					fmt.Fprint(ot.fsumWriter, "\n")

					//print the stack
					//if l := o.StackTop.Len(); l>0 {
					//	fmt.Fprintf(ot.summary, "\t%d:", o.MaxStack)
					//	for i := 0; i < l; i++ {
					//		fmt.Fprintf(ot.summary, "%x ", o.StackTop.Back(i))
					//	}
					//}

					//print the Rstack
					//if o.MaxRStack > 0 {
					//	fmt.Fprintf(ot.fsumWriter, "\trs:%d:", o.MaxRStack)
					//	//fmt.Printf("return stack used in block %d, tx %s", BlockNum)
					//	for i := 0; i < o.MaxRStack; i++ {
					//		fmt.Fprintf(ot.fsumWriter, "%x ", o.RetStackTop[i])
					//	}
					//}
				}
			}
			isTxFault := t.Fault != ""
			if !isTxFault {
				continue
			}
			ths := ""
			if t.TxHash != nil {
				ths = t.TxHash.String()
			}
			fmt.Fprintf(ot.fsumWriter, "Tx FAULT\tb=%d opF=%s\tTxF=%s\ttaddr=%s\ttx=%s\n", blockNum, t.OpcodeFault, t.Fault, t.TxAddr, ths)

		}

		if saveOpcodes {
			// just save everything
			bt := blockTxs{&blockNum, &ot.Txs}
			err = fopsEnc.Encode(bt)
			check(err)
		}

/*		sd := make([]segmentDump, 0, len(ot.Txs))
		var i int
		for i  = range ot.Txs  {
			t := ot.Txs[i]
			segs := CreateSegments(t)
			var th, ch string
			if t.TxHash != nil {
				th = t.TxHash.String()
			}
			if t.CodeHash != nil {
				ch = t.CodeHash.String()
			}

			sd = append(sd, segmentDump{th, t.TxAddr, ch, segs})
			//fmt.Printf("Encoded tx %s with %d segs\n", t.TxAddr, len(segs))

		}
		bs := blockSegments{blockNum, sd}
		//fileSegmentsEncoder.Encode(blockNum)
		err = fsegEnc.Encode(bs)
		check(err)*/


		//fmt.Printf("buffered %d", fileSegmentsWriter.Buffered())
		//fileSegmentsWriter.Flush()


		// dump all the data as JSON
		// surround the Tx array with a block number map entry
/*		if alreadyWrote {
			fsjWriter.WriteString(",")
		}
		fsjWriter.WriteString("\""+strconv.Itoa(int(blockNum))+"\":\n")
		//json, err := json.Marshal(ot.Txs)//json.MarshalIndent(ot.Txs, "", fmt.Sprintf("\t"))
		//fsjWriter.Write(json)
		_, err = easyjson.MarshalToWriter(ot.Txs, fsjWriter)
		check(err)
		//fsjWriter.Write(json)
		alreadyWrote = true*/


		blockNum++
		if len(ot.txsInDepth) != 1 || len(ot.stack) !=0 {
			panic(fmt.Sprintf("At end of block, tracer should be almost reset but isn't: lstack=%d, lTID=%d, TID[0]=%d",
				len(ot.stack), len(ot.txsInDepth),ot.txsInDepth[0]))
		}
		ot.Txs = nil
		ot.txsInDepth[0] = 0
		ot.blockNumber = blockNum

		//ot = NewOpcodeTracer(blockNum, saveOpcodes, saveSegments)



		// Check for interrupts
		select {
		case interrupt = <-interruptCh:
			fmt.Println("interrupted, please wait for cleanup...")
		default:
		}

		if blockNum>=blockNumOrig + numBlocks {
			interrupt = true
		}

		if interrupt || blockNum%1000 == 0 {
			bps := float64(blockNum-blockNumOrig)/time.Since(startTime).Seconds()
			bpss := fmt.Sprintf("%.2f", bps)
			log.Info("Checked", "blocks", blockNum, "blocks/s", bpss)

			//close current files
			if saveOpcodes {
				fopsWriter.Flush()
				fops.Close()
				fops = nil
			}

			ot.fsumWriter.Flush()
			fi, err := fsum.Stat()
			if err != nil {
				log.Error(err.Error())
			}
			if fi.Size() == 0 {
				os.Remove(fi.Name())
			} else {
				log.Info("Wrote summary file")
			}
			//if fi.Size() > 1000000000 { //~1GB
				fsum.Close()
				fsum = nil
			//}

			if saveSegments {
				fsegWriter.Flush()
				fseg.Close()
				fseg = nil
			}

/*			fsjWriter.WriteString("\n}")
			fsjWriter.Flush()
			fsegJson.Close()
			fsegJson = nil
*/

		}
	}
	if writeReceipts {
		log.Info("Committing final receipts", "batch size", common.StorageSize(batch.BatchSize()))
		if _, err := batch.Commit(); err != nil {
			return err
		}
	}

	bps := float64(blockNum-blockNumOrig)/time.Since(startTime).Seconds()
	bpss := fmt.Sprintf("%.2f", bps)
	log.Info("Checked", "blocks", blockNum, "next time specify --block", blockNum, "duration", time.Since(startTime), "blocks/s", bpss)

	/*

	f4, err := os.Open("./segments.gzip")
	check(err)
	defer f4.Close()
	segReader, _ := gzip.NewReader(f4)
	defer segReader.Close()
	segDec := gob.NewDecoder(segReader)
	bs := new(blockSegments)
	//var err error
	count :=  0
	//var bn uint64
	//err = segDec.Decode(&bn)
	for {
		err = segDec.Decode(&bs)
		if err != nil {
			break
		}
		count++
		//fmt.Fprintf(summary, "Decoded blockSegments b=%d, nsegs=%d\n", bs.BlockNum, len(bs.Segments))
		//fmt.Printf("Decoded blockSegments b=%d, nsegs=%d\n", bs.BlockNum, len(bs.Segments))

		//for i := range *bs.Segments {
		//	bss := &((*bs.Segments)[i])
		//	fmt.Fprintf(summary, "\tEntry %d txaddr=%s segs=%d tx=%s ch=%s\n", i, bss.TxAddr, len(bss.Segments), bss.Tx, bss.CodeHash)
		//	//for i:= range bss.Segments {
		//	//	s := &bss.Segments[i]
		//	//	fmt.Fprintf(summary, "\t\tSeg%d %x-%x\n", i, s.Start, s.End)
		//	//}
		//}
		//fmt.Fprintf(summary, "")
	}
	fmt.Printf( "Decoded %d, err=%s\n", count, err.Error())

*/
	return nil
}
