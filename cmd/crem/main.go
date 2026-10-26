package main

import (
	"os"

	"github.com/damian-kolasinski/crem/internal/cli"
)

// version is set at release time with -ldflags "-X main.version=<version>".
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.Streams{Out: os.Stdout, Err: os.Stderr}, version))
}
