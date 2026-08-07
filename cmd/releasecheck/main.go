package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/1337lean/relaybox/internal/distcheck"
)

func main() {
	directory := flag.String("dist", "dist", "GoReleaser distribution directory")
	version := flag.String("version", "", "expected tag or archive version (optional for snapshots)")
	validateTag := flag.String("validate-tag", "", "validate one v-prefixed semantic release tag and exit")
	smoke := flag.Bool("smoke", true, "run the archive executable for this host")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "releasecheck does not accept positional arguments")
		os.Exit(2)
	}
	if *validateTag != "" {
		if _, err := distcheck.ValidateTag(*validateTag); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "validated Relaybox release tag", *validateTag)
		return
	}
	if err := distcheck.Verify(*directory, *version, *smoke); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "verified all Relaybox release archives and checksums")
}
