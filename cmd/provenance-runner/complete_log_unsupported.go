//go:build !linux

package main

import "errors"

func exportCompleteLogFile(string, []byte) error {
	return errors.New("complete-log export requires Linux O_TMPFILE support")
}
