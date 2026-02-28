package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Banner is the ASCII art logo printed before all CLI output.
const Banner = "\033[32m\033[1m" +
	"  ___  _  _ __   __ ___ _____ \n" +
	" / __|| \\| |\\ \\ / /| __|_   _|\n" +
	" \\__ \\| .`" + " | \\ V / | _|  | |  \n" +
	" |___/|_|\\_|  |_|  |_|   |_|  " +
	"\033[0m\n" +
	"\033[2m  Supply Chain Risk Analyzer\033[0m\n"

var rootCmd = &cobra.Command{
	Use:   "snyft",
	Short: "Supply chain security analyzer for dependencies",
	Long: `Snyft analyzes dependencies from Python, JavaScript, and Java projects
to evaluate supply chain security risks by examining source code availability,
repository health, build infrastructure, and potential compromise indicators.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		fmt.Fprint(os.Stderr, Banner)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Customize the help template to include the ASCII art banner.
	// cobra doesn't call PersistentPreRun when displaying help, so the
	// banner is prepended to the help template instead.
	defaultHelp := rootCmd.HelpTemplate()
	rootCmd.SetHelpTemplate(Banner + "\n" + defaultHelp)
}
