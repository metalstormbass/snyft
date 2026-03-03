package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	// Version information, set by GoReleaser or Makefile ldflags during build.
	// When installed via "go install ...@vX.Y.Z", these defaults are
	// overridden at startup by the module info Go embeds in the binary.
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func init() {
	rootCmd.AddCommand(versionCmd)

	// If ldflags were not used (Version is still "dev"), try to read
	// the version that "go install" embeds in every binary.
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				Version = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if len(s.Value) >= 12 {
						Commit = s.Value[:12]
					} else if s.Value != "" {
						Commit = s.Value
					}
				case "vcs.time":
					if s.Value != "" {
						Date = s.Value
					}
				}
			}
		}
	}
}

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

