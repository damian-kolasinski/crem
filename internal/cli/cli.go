// Package cli maps crem's command line onto its use cases.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Streams are the outputs a command writes to.
type Streams struct {
	Out io.Writer
	Err io.Writer
}

// Run executes the command line and returns the process exit code.
func Run(args []string, streams Streams, version string) int {
	root := newRootCommand(streams, version)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(streams.Err, "crem: %v\n", err)
		return 1
	}
	return 0
}

func newRootCommand(streams Streams, version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "crem",
		Short:         "Keep Apple code signing healthy: certificates, provisioning profiles, and CI secrets",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	return root
}
