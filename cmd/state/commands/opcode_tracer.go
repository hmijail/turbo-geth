package commands

import (
	"github.com/ledgerwatch/turbo-geth/cmd/state/stateless"
	"github.com/spf13/cobra"
)

var (
	historyfile   string
	nocheck       bool
	writeReceipts bool
	numBlocks	  uint64
	saveOpcodes	  bool
	saveSegments  bool
)

func init() {
	withBlock(opcodeTracer)
	withChaindata(opcodeTracer)
	opcodeTracer.Flags().StringVar(&historyfile, "historyfile", "", "path to the file where the changesets and history are expected to be. If omitted, the same as --chaindata")
	opcodeTracer.Flags().Uint64Var(&numBlocks, "numBlocks", 1, "number of blocks to run the operation on")
	opcodeTracer.Flags().BoolVar(&saveOpcodes, "saveOpcodes", false, "set to save the opcodes")
	opcodeTracer.Flags().BoolVar(&saveSegments, "saveSegments", false, "set to save the segments")


	rootCmd.AddCommand(opcodeTracer)
}

var opcodeTracer = &cobra.Command{
	Use:   "opcodeTracer",
	Short: "Re-executes historical transactions in read-only mode and traces them at the opcode level",
	RunE: func(cmd *cobra.Command, args []string) error {
		return stateless.OpcodeTracer(genesis, block, chaindata, historyfile, numBlocks, saveOpcodes, saveSegments)
	},
}
