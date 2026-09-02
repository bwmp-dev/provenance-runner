//go:build !linux

package gatewayclient

import "os"

func privateFileMetadata(os.FileInfo) bool { return true }
