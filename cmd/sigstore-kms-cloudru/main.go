package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"

	"github.com/franchb/sigstore-kms-cloudru/pkg/cloudru"
)

const (
	expectedProtocolVersion = "v1"

	// minPluginArgs is the argv length required to carry a protocol version.
	minPluginArgs = 2
)

var (
	errMissingProtocolVersion  = errors.New("missing protocol version")
	errExpectedProtocolVersion = errors.New("expected protocol version")
)

func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, cloudru.LoadSignerVerifier))
}

func run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	load func(context.Context, string) (*cloudru.SignerVerifier, error),
) int {
	if len(args) < minPluginArgs {
		return writeError(stdout, errMissingProtocolVersion)
	}

	if protocolVersion := args[1]; protocolVersion != expectedProtocolVersion {
		return writeError(
			stdout,
			fmt.Errorf("%w %s, got %s", errExpectedProtocolVersion, expectedProtocolVersion, protocolVersion),
		)
	}

	pluginArgs, err := handler.GetPluginArgs(args)
	if err != nil {
		return writeError(stdout, err)
	}

	signerVerifier, err := load(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		return writeError(stdout, err)
	}

	if _, err := handler.Dispatch(stdout, stdin, pluginArgs, signerVerifier); err != nil {
		return 1
	}

	return 0
}

func writeError(stdout io.Writer, err error) int {
	_ = handler.WriteErrorResponse(stdout, err)

	return 1
}
