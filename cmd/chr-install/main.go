package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/parhamfa/chr-install/internal/app"
	"github.com/parhamfa/chr-install/internal/install"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--internal-writer" {
		if err := install.RunWriter(os.Args[2], true); err != nil {
			install.HaltWriter(err)
		}
		return
	}
	flags := flag.NewFlagSet("chr-install", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	preflightOnly := flags.Bool("preflight", false, "inspect the server without changing it")
	showVersion := flags.Bool("version", false, "print version information")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: chr-install [--preflight] [--version]")
		fmt.Fprintln(flags.Output(), "\nInteractively replace a supported Debian or Ubuntu installation with MikroTik CHR.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(2)
	}
	if *showVersion {
		fmt.Printf("chr-install %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := app.Run(ctx, app.Options{PreflightOnly: *preflightOnly, Output: os.Stdout}); err != nil {
		fmt.Fprintf(os.Stderr, "chr-install: %v\n", err)
		os.Exit(1)
	}
}
