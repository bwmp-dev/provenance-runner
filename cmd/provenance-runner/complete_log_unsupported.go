//go:build !linux

package main

import (
	"errors"
	"io"
)

func exportCompleteLogFile(string, io.Reader) error {
	return errors.New("complete-log export requires Linux O_TMPFILE support")
}
