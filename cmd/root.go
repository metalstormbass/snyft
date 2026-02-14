package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "snyft",
	Short: "Supply chain security analyzer for dependencies",
	Long: `Snyft analyzes dependencies from Python, JavaScript, and Java projects
to evaluate supply chain security risks by examining source code availability,
repository health, build infrastructure, and potential compromise indicators.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
