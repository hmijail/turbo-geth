package commands

import (
	"github.com/ledgerwatch/turbo-geth/cmd/state/stateless"
	"github.com/spf13/cobra"
)

var (
	//historyfile   string
	//nocheck       bool
	//writeReceipts bool
)

func init() {
	withBlock(opcodeTracerCmd)
	withChaindata(opcodeTracerCmd)
	opcodeTracerCmd.Flags().StringVar(&historyfile, "historyfile", "", "path to the file where the changesets and history are expected to be. If omitted, the same as --chaindata")
	opcodeTracerCmd.Flags().BoolVar(&nocheck, "nocheck", false, "set to turn off the changeset checking and only execute transaction (for performance testing)")
	opcodeTracerCmd.Flags().BoolVar(&writeReceipts, "writeReceipts", false, "set to turn off writing receipts as the exection ongoing")
	rootCmd.AddCommand(opcodeTracerCmd)
}

var opcodeTracerCmd = &cobra.Command{
	Use:   "opcodeTracer",
	Short: "Re-executes historical transactions in read-only mode and lists opcodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		return stateless.OpcodeTracer(genesis, block, chaindata, historyfile, nocheck, writeReceipts)
	},
}
