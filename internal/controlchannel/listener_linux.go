//go:build linux

package controlchannel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const SocketName = "control.sock"

// RootListener retains a provisioned root-owned 0711 directory and creates one
// exclusive 0660 socket for the provisioned worker group. SO_PEERCRED still
// requires the exact worker UID; filesystem group membership is not authority.
// It never removes a pre-existing socket or adopts a foreign replacement.
type RootListener struct {
	mu, acceptMu                               sync.Mutex
	parent                                     *os.File
	listener                                   *net.UnixListener
	workerUID, workerGID                       uint32
	parentDev, parentIno, socketDev, socketIno uint64
	stopped, closed                            bool
}

func OpenRootListener(parent *os.File, workerUID, workerGID uint32) (owned *RootListener, result error) {
	groups, err := os.Getgroups()
	if os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || parent == nil || workerUID == 0 || workerGID == 0 || workerUID == ^uint32(0) || workerGID == ^uint32(0) {
		return nil, ErrChannel
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrChannel
	}
	l := &RootListener{parent: os.NewFile(uintptr(fd), "measured-control-directory"), workerUID: workerUID, workerGID: workerGID}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode != unix.S_IFDIR|0711 {
		_ = l.parent.Close()
		return nil, ErrChannel
	}
	l.parentDev, l.parentIno = uint64(st.Dev), st.Ino
	if err := unix.Fstatat(fd, SocketName, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		_ = l.parent.Close()
		return nil, ErrChannel
	}
	address := &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", fd, SocketName), Net: "unixpacket"}
	l.listener, err = net.ListenUnix("unixpacket", address)
	if err != nil {
		_ = l.parent.Close()
		return nil, ErrChannel
	}
	l.listener.SetUnlinkOnClose(false)
	// Parent is root-only writable. Record the socket inode before changing its
	// access mode; acceptance is impossible until all validation has completed.
	if unix.Fstatat(fd, SocketName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 {
		_ = l.listener.Close()
		l.stopped = true
		// No inode identity means no permission to unlink. Retain the directory
		// and return the partial owner rather than abandon an unknown entry.
		return l, ErrChannel
	}
	l.socketDev, l.socketIno = uint64(st.Dev), st.Ino
	if unix.Fchownat(fd, SocketName, 0, int(workerGID), unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fchmodat(fd, SocketName, 0660, 0) != nil || !l.validLocked() {
		return l, errors.Join(ErrChannel, l.Close())
	}
	return l, nil
}

func (l *RootListener) validLocked() bool {
	if l == nil || l.parent == nil || l.listener == nil || l.stopped || l.closed {
		return false
	}
	var parent, socket unix.Stat_t
	fd := int(l.parent.Fd())
	return unix.Fstat(fd, &parent) == nil && parent.Uid == 0 && parent.Mode == unix.S_IFDIR|0711 && uint64(parent.Dev) == l.parentDev && parent.Ino == l.parentIno && unix.Fstatat(fd, SocketName, &socket, unix.AT_SYMLINK_NOFOLLOW) == nil && socket.Mode == unix.S_IFSOCK|0660 && socket.Uid == 0 && socket.Gid == l.workerGID && uint64(socket.Dev) == l.socketDev && socket.Ino == l.socketIno
}

func (l *RootListener) Accept(deadline time.Time) (*Channel, error) {
	if l == nil {
		return nil, ErrChannel
	}
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	l.mu.Lock()
	valid := validDeadline(deadline) && l.validLocked()
	if !valid {
		l.stopped = true
	}
	listener := l.listener
	l.mu.Unlock()
	if !valid {
		return nil, ErrChannel
	}
	if listener.SetDeadline(deadline) != nil {
		return nil, ErrChannel
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		return nil, errors.Join(ErrChannel, err)
	}
	l.mu.Lock()
	valid = l.validLocked()
	if !valid {
		l.stopped = true
	}
	l.mu.Unlock()
	if !valid {
		_ = conn.Close()
		return nil, ErrChannel
	}
	channel, err := New(conn, l.workerUID)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return channel, nil
}

// Close closes admission immediately. A replaced directory entry is retained
// untouched and reports refusal; callers must not substitute broad path cleanup.
func (l *RootListener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.stopped = true
	if l.listener != nil {
		if err := l.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return ErrChannel
		}
	}
	if l.parent == nil {
		return ErrChannel
	}
	fd := int(l.parent.Fd())
	var st unix.Stat_t
	err := unix.Fstatat(fd, SocketName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFSOCK || uint64(st.Dev) != l.socketDev || st.Ino != l.socketIno {
			return ErrChannel
		}
		if unix.Unlinkat(fd, SocketName, 0) != nil {
			return ErrChannel
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return ErrChannel
	}
	if l.parent.Close() != nil {
		return ErrChannel
	}
	l.closed = true
	return nil
}
