package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var stdinReader = bufio.NewReader(os.Stdin)

// promptSecret reads a secret without echo when stdin is a terminal, and
// falls back to reading a line (for scripted/piped use, e.g. tests).
func promptSecret(label string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	return bytes.TrimRight([]byte(line), "\r\n"), nil
}

// promptSecretConfirm prompts twice and requires both entries to match.
func promptSecretConfirm(label string) ([]byte, error) {
	first, err := promptSecret(label)
	if err != nil {
		return nil, err
	}
	second, err := promptSecret(label + " (confirm)")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("entries do not match")
	}
	for i := range second {
		second[i] = 0
	}
	return first, nil
}

// promptLine reads a visible line (used for TOTP codes).
func promptLine(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
