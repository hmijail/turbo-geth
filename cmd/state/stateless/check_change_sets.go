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

type opcode struct {
	Pc       		uint64
	Op       		vm.OpCode
	//StackTop 		*stack.Stack
	//StackTop 		[]uint256.Int
	RetStackTop		RetStackTop
	MaxStack 		int
	MaxRStack 		int
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
	Input 			SliceBytes //ByteSliceAsHex
	//Segments 		[]segment
	Create			bool
	Fault 			string
	Opcodes         SliceOpcodes
}

type	SliceBytes 		[]byte
type 	SliceOpcodes	[]opcode

type opcodeTracer struct {
	Txs             	slicePtrTx
	//detail, summary   	*bufio.Writer
	//c 					int
	stack 				slicePtrTx
	//stackIndexes		[]int
	showNext			bool
	lastLine			string
	txsInDepth			[]int8

}

//easyjson:json
type	slicePtrTx	[]*tx

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
	Start 	uint64
	End		uint64
}

type segmentDump struct {
	Tx			string
	TxAddr		string
	CodeHash	string
	Segments 	[]segment
}

type blockSegments struct {
	BlockNum uint64
	Segments []segmentDump
}

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
	newTx := tx{From: from, To: to,  Create: create, Input: input, Depth: depth, TxAddr: txAddr}
	ot.Txs = append(ot.Txs, &newTx)

	// take note in our own stack that the tx stack has grown
	//ltxs := len(ot.Txs)
	ot.stack = append(ot.stack, &newTx)

	ot.showNext = true

	//fmt.Fprintf(ot.summary, "%sStart addr=%s from=%v to=%v d=%d \n", strings.Repeat("\t",depth), txAddr, from.String(), to.String(),depth)

	return nil
}

func (ot *opcodeTracer) CaptureEnd(depth int, output []byte, gasUsed uint64, t time.Duration, err error) error {
	//lt := len(ot.Txs)
	//lastEntry := &ot.Txs[lt-1]

	// When a CaptureEnd is called, a Tx has finished. Pop our stack
	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]
	// sanity check: depth of stack == depth reported by system
	if ls-1 != depth || depth != currentEntry.Depth {
		panic(fmt.Sprintf("End of Tx at d=%d but stack has d=%d and entry has d=%", depth, ls, currentEntry.Depth))
	}
	ot.stack = ot.stack[ : ls-1]
	errstr := ""
	if err != nil {
		errstr = err.Error()
	}
	currentEntry.Fault = errstr
	ot.txsInDepth = ot.txsInDepth[:depth+1]


	//fmt.Fprint(ot.summary, ot.lastLine)
	ot.lastLine = ""



	//fmt.Fprintf(ot.summary, "%sEnd d=%v ops=%d", strings.Repeat("\t",depth), depth, len(currentEntry.Opcodes))
	//if err != nil {
	//	fmt.Fprintf(ot.summary, " e=%v", err.Error())
	//}
	//fmt.Fprintf(ot.summary, "\n")
	//ot.summary.Flush()



	//if the finished transaction was only a value transfer (no opcodes), then we're not interested in it. Remove it from our list.
	// if there were opcodes, the entry would have been fully init'ed, and so it would have a TxHash
	// also, a tx without opcodes can't have subordinate txs
	//if currentEntry.TxHash == "" {
	//	//fmt.Printf("Dumping value tx from %s\n", currentEntry.From.String())
	//	fmt.Fprintf(ot.summary,"%sDumping value tx from %s\n", strings.Repeat("\t",depth), currentEntry.From.String())
	//	lt := len(ot.Txs)
	//	ot.Txs = ot.Txs[:lt-1]
	//}

	ot.showNext = true
	return nil
}

func (ot *opcodeTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, st *stack.Stack, retst *stack.ReturnStack, rData []byte, contract *vm.Contract, opDepth int, err error) error {

	currentTxHash := env.TxHash
	currentTxDepth := opDepth - 1

	ls := len(ot.stack)
	currentEntry := ot.stack[ls-1]

	//sanity check
	if currentEntry.Depth != currentTxDepth {
		panic(fmt.Sprintf("Depth should be the same but isn't: current tx's %d, current entry's %d", currentTxDepth, currentEntry.Depth))
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


	lrs := len(retst.Data())
	var retStackTop []uint32
	if lrs>0 {
		retStackTop = make([]uint32, lrs, lrs)
		copy(retStackTop, retst.Data())
	}



	// is the Tx entry still not fully initialized?
	if currentEntry.TxHash == nil {
		// CaptureStart creates the entry for a new Tx, but doesn't have access to EVM data, like the Tx Hash
		// here we assume that the tx entry was recently created by CaptureStart
		// AND this is the first CaptureState that has happened since then
		// AND that both Captures are for the same transaction
		// AND that we can't go into another depth without executing at least 1 opcode
		// Note that the only connection between both that we can notice is that the current op's depth should be lastTxEntry.Depth+1

		// fill in the missing data in the entry
		currentEntry.TxHash = new(common.Hash)
		currentEntry.TxHash.SetBytes(currentTxHash.Bytes())
		currentEntry.CodeHash = new(common.Hash)
		currentEntry.CodeHash.SetBytes(contract.CodeHash.Bytes())
		currentEntry.Opcodes = make([]opcode, 0, 200)
		//fmt.Fprintf(ot.w, "%sFilled in TxHash\n", strings.Repeat("\t",depth))
	}


/*
	line := fmt.Sprintf("%s%d-%s", strings.Repeat("\t", currentTxDepth), currentTxDepth, currentTxHash )
	line += fmt.Sprintf("\tpc=%x op=%s ops=%d", pc, op.String(), len(currentEntry.Opcodes))
	if err != nil {
		line += fmt.Sprintf(" ---- e=%v", err.Error())
	}
	line += fmt.Sprintf("\n")

	if ot.showNext {
		//fmt.Fprintf(ot.summary, line)
		ot.showNext = false
	}

	ot.lastLine = line
*/
	//store the opcode and its related data
	errstr := ""
	if err != nil {
		errstr = err.Error()
	}
	newOpcode := opcode{pc, op, retStackTop, st.Len(), lrs, errstr}
	currentEntry.Opcodes = append(currentEntry.Opcodes, newOpcode)

	return nil
}
func (ot *opcodeTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, rst *stack.ReturnStack, contract *vm.Contract, depth int, err error) error {
	ot.CaptureState(env, pc, op, gas, cost, memory, stack, rst, nil, contract, depth, err)

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
	res := new(opcodeTracer)
	res.txsInDepth = make([]int8,1,4)
	res.stack = make([]*tx, 0, 8)
	res.Txs = make([]*tx, 0, 50)
	return res
}

func CreateSegments(t *tx) (segments []segment) {
	// digest the series of opcodes into Segments

	if len(t.Opcodes) == 0 {
		return nil
	}

	segments = make([]segment, 0, 8)
	//fmt.Printf("tx %d-%s -\n", t.Depth, t.TxHash)
	var lastOpWasPush 	bool
	var lastPc   		uint64
	var lastOp			vm.OpCode = 0xfe // op INVALID
	//firstSegment := true
	//t.Segments = append(t.Segments, segment{})
	//startPc := 0
	for i := range t.Opcodes {
		o := t.Opcodes[i]
		ls := len(segments)
		if (ls>0) && (o.Pc == lastPc+1 || lastOpWasPush) { // not the first segment, and no discontinuity
			lastPc = o.Pc
			lastOpWasPush = o.Op.IsPush()
			lastOp = o.Op
		} else {
			// we have a discontinuity in the control flow. Record the end of the past segment and start a new one
			//ls := len(t.Segments)
			if ls>0 {
				segments[ls-1].End = lastPc
				//fmt.Printf("End\t%x\t%s\n", lastPc, lastOp.String())
			}
			segments = append(segments, segment{Start:  o.Pc})
			//fmt.Printf("Start\t%x\t%s\n", o.Pc.uint64, o.Op.String())
			//sanity check
			if o.Op.IsPush() && o.Pc != 0 {
				panic(fmt.Sprintf("First op at non-first segment is a PUSH - this is impossible, should be JUMPDEST. pc=%x, lastpc=%x, lastOp=%s, tx=%d-%s", o.Pc,  lastPc, lastOp.String(), t.Depth, t.TxHash))
			}

			lastPc = o.Pc
			lastOpWasPush = o.Op.IsPush()
			lastOp = o.Op
		}
	}
	ls := len(segments)
	segments[ls-1].End = lastPc
	//fmt.Printf("%d Segments, last = %v\n", ls, t.Segments[ls-1])

	return segments
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

	ot := NewOpcodeTracer()



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

	var fsum, fseg /*, fsegJson*/ *os.File
	var fsegWriter, fsumWriter /*, fsjWriter*/ *bufio.Writer
	var fsegEnc *gob.Encoder
	for !interrupt {
		block := bc.GetBlockByNumber(blockNum)
		if block == nil {
			break
		}

		bnStr := strconv.Itoa(int(blockNum))
		if fops == nil {
			fops, err = os.Create("./opcodes-"+bnStr)
			check(err)
			fopsWriter = bufio.NewWriter(fops)
			fopsEnc = gob.NewEncoder(fopsWriter)
		}

		if fseg == nil {
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
			fsumWriter = bufio.NewWriter(fsum)
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


		// write a text summary of interesting things
		numOpcodes := 0
		for _ , t := range ot.Txs {

			for i := range t.Opcodes {
				o := &t.Opcodes[i]
				//only print to the summary the opcodes that are interesting
				if (o.MaxRStack != 0) { //|| (o.Fault != nil) {
					//pass
				} else {
					continue
				}


				fmt.Fprintf(fsumWriter, "b=%d taddr=%s f=%s tx=%s\n", blockNum, t.TxAddr, t.Fault, t.TxHash)
/*
				fmt.Fprintf(summary, "%d\t%x\t%-20s", i, o.Pc.uint64, o.Op.String())
				if o.Fault != nil {
					fmt.Fprintf(summary, "FAULT:%s", o.Fault.Error())
				}
*/

				//print the stack
				//if l := o.StackTop.Len(); l>0 {
				//	fmt.Fprintf(ot.summary, "\t%d:", o.MaxStack)
				//	for i := 0; i < l; i++ {
				//		fmt.Fprintf(ot.summary, "%x ", o.StackTop.Back(i))
				//	}
				//}

				//print the Rstack
				if o.MaxRStack > 0 {
					fmt.Fprintf(fsumWriter, "\trs:%d:", o.MaxRStack)
					//fmt.Printf("return stack used in block %d, tx %s", BlockNum)
					for i := 0; i < o.MaxRStack; i++ {
						fmt.Fprintf(fsumWriter, "%x ", o.RetStackTop[i])
					}
				}

				fmt.Fprint(fsumWriter, "\n")
			}
			numOpcodes += len(t.Opcodes)
		}

		bt := blockTxs{&blockNum, &ot.Txs}
		err = fopsEnc.Encode(bt)
		check(err)


		sd := make([]segmentDump, 0, len(ot.Txs))
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
		check(err)


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



		ot.Txs = nil
		ot.txsInDepth[0] = 0
		//ot = NewOpcodeTracer()

		blockNum++
		if blockNum%1000 == 0 {
			log.Info("Checked", "blocks", blockNum)

			//close current files
			fopsWriter.Flush()
			fops.Close()
			fops = nil

			fsumWriter.Flush()
			fsum.Close()
			fsum = nil

			fsegWriter.Flush()
			fseg.Close()
			fseg = nil

/*			fsjWriter.WriteString("\n}")
			fsjWriter.Flush()
			fsegJson.Close()
			fsegJson = nil*/

		}

		// Check for interrupts
		select {
		case interrupt = <-interruptCh:
			fmt.Println("interrupted, please wait for cleanup...")
		default:
		}

		if blockNum>=blockNumOrig + numBlocks {
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

	fopsWriter.Flush()
	fops.Close()
	fops = nil

	fsumWriter.Flush()
	fsum.Close()
	fsum = nil

	fsegWriter.Flush()
	fseg.Close()
	fseg = nil

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
