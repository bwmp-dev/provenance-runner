//go:build linux

package gatewayclient

import (
	"os"
	"syscall"
)

func privateFileMetadata(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
