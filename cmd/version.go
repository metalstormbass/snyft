package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Version information, set by GoReleaser during build
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Display the version, commit hash, and build date of snyft.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("snyft version %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built at: %s\n", Date)
		fmt.Printf("  go version: %s\n", runtime.Version())
		fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
