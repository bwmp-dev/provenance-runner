//go:build linux

// Package controlchannel provides bounded, peer-authenticated local framing.
// It does not authorize jobs, interpret payloads or expose an execution service.
package controlchannel

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaximumPayload = 64 << 10
	MaximumFiles   = 16
	headerSize     = 24
)

var ErrChannel = errors.New("measured_control_channel_refused")

type Kind byte

const (
	Start Kind = iota + 1
	Reconcile
	Release
	Cancel
	Result
	Observation
	Completion
)

// Packet files are borrowed for Send and owned by the recipient after Receive.
// Only read-only regular files can cross this channel. Hash and role validation
// are separate mandatory admission checks; a received file is not trusted.
type Packet struct {
	Kind     Kind
	Sequence uint64
	Payload  []byte
	Files    []*os.File
}

type Channel struct {
	conn                        *net.UnixConn
	peer                        uint32
	readMu, writeMu             sync.Mutex
	readSequence, writeSequence uint64
}

// New transfers connection ownership only on success. expectedUID comes from
// local provisioning, never from an incoming payload. Clients must require UID
// zero; the service must require its provisioned, non-root worker UID.
func New(conn *net.UnixConn, expectedUID uint32) (*Channel, error) {
	if conn == nil || expectedUID == ^uint32(0) {
		return nil, ErrChannel
	}
	c := &Channel{conn: conn, peer: expectedUID}
	if !c.validPeer() {
		return nil, ErrChannel
	}
	return c, nil
}

func (c *Channel) validPeer() bool {
	if c == nil || c.conn == nil {
		return false
	}
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return false
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		kind, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		peer, pe := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		address, ae := unix.Getpeername(int(fd))
		_, local := address.(*unix.SockaddrUnix)
		valid = e == nil && kind == unix.SOCK_SEQPACKET && pe == nil && peer.Pid > 0 && peer.Uid == c.peer && ae == nil && local
	})
	return err == nil && valid
}

func (c *Channel) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func validDeadline(deadline time.Time) bool {
	remaining := time.Until(deadline)
	return remaining > 0 && remaining <= 30*time.Second
}

func validKind(k Kind) bool { return k >= Start && k <= Completion }

func readonlyRegular(fd int) bool {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var st unix.Stat_t
	return err == nil && flags&unix.O_ACCMODE == unix.O_RDONLY && flags&unix.O_PATH == 0 && unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Size >= 0
}

func (c *Channel) Send(packet Packet, deadline time.Time) (result error) {
	if c == nil || c.conn == nil {
		return ErrChannel
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	defer func() {
		if result != nil {
			_ = c.Close()
		}
	}()
	if !validDeadline(deadline) || !c.validPeer() || !validKind(packet.Kind) || packet.Sequence == 0 || packet.Sequence != c.writeSequence+1 || len(packet.Payload) > MaximumPayload || len(packet.Files) > MaximumFiles {
		return ErrChannel
	}
	fds := make([]int, 0, len(packet.Files))
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	for _, file := range packet.Files {
		if file == nil {
			return ErrChannel
		}
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return ErrChannel
		}
		fds = append(fds, fd)
		if !readonlyRegular(fd) {
			return ErrChannel
		}
	}
	data := make([]byte, headerSize+len(packet.Payload))
	copy(data[:4], "PVC1")
	data[4], data[5] = 1, byte(packet.Kind)
	binary.BigEndian.PutUint64(data[8:16], packet.Sequence)
	binary.BigEndian.PutUint32(data[16:20], uint32(len(packet.Payload)))
	binary.BigEndian.PutUint16(data[20:22], uint16(len(fds)))
	copy(data[headerSize:], packet.Payload)
	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	if c.conn.SetWriteDeadline(deadline) != nil {
		return ErrChannel
	}
	n, oob, err := c.conn.WriteMsgUnix(data, rights, nil)
	if err != nil || n != len(data) || oob != len(rights) {
		return errors.Join(ErrChannel, err)
	}
	c.writeSequence = packet.Sequence
	return nil
}

func (c *Channel) Receive(deadline time.Time) (packet Packet, result error) {
	if c == nil || c.conn == nil {
		return Packet{}, ErrChannel
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	defer func() {
		if result != nil {
			_ = c.Close()
		}
	}()
	if !validDeadline(deadline) || !c.validPeer() || c.conn.SetReadDeadline(deadline) != nil {
		return Packet{}, ErrChannel
	}
	data := make([]byte, headerSize+MaximumPayload)
	oob := make([]byte, unix.CmsgSpace(MaximumFiles*4))
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return Packet{}, ErrChannel
	}
	var n, control, flags int
	var receiveErr error
	err = raw.Read(func(fd uintptr) bool {
		n, control, flags, _, receiveErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
		return receiveErr != unix.EAGAIN && receiveErr != unix.EWOULDBLOCK && receiveErr != unix.EINTR
	})
	// Parse and retain all delivered rights before any framing refusal, so even
	// a truncated/malformed packet cannot leak descriptors into this process.
	var received []int
	defer func() {
		if result != nil {
			for _, fd := range received {
				_ = unix.Close(fd)
			}
		}
	}()
	ancillaryValid := true
	messageCount := 0
	remaining := oob[:control]
	for len(remaining) != 0 {
		if len(remaining) < unix.CmsgLen(0) {
			ancillaryValid = false
			break
		}
		header, body, rest, parseErr := unix.ParseOneSocketControlMessage(remaining)
		if parseErr != nil {
			ancillaryValid = false
			break
		}
		remaining = rest
		messageCount++
		if header.Level != unix.SOL_SOCKET || header.Type != unix.SCM_RIGHTS {
			ancillaryValid = false
			continue
		}
		if len(body)%4 != 0 {
			ancillaryValid = false
			break
		}
		fds, e := unix.ParseUnixRights(&unix.SocketControlMessage{Header: header, Data: body})
		if e != nil {
			ancillaryValid = false
			continue
		}
		received = append(received, fds...)
	}
	if err != nil || receiveErr != nil || !ancillaryValid || messageCount > 1 || len(received) > MaximumFiles || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < headerSize {
		return Packet{}, errors.Join(ErrChannel, err, receiveErr)
	}
	if string(data[:4]) != "PVC1" || data[4] != 1 || !validKind(Kind(data[5])) || data[6] != 0 || data[7] != 0 || data[22] != 0 || data[23] != 0 || binary.BigEndian.Uint64(data[8:16]) == 0 || int(binary.BigEndian.Uint32(data[16:20])) != n-headerSize || int(binary.BigEndian.Uint16(data[20:22])) != len(received) {
		return Packet{}, ErrChannel
	}
	for _, fd := range received {
		if !readonlyRegular(fd) {
			return Packet{}, ErrChannel
		}
	}
	sequence := binary.BigEndian.Uint64(data[8:16])
	if sequence != c.readSequence+1 {
		return Packet{}, ErrChannel
	}
	c.readSequence = sequence
	packet = Packet{Kind: Kind(data[5]), Sequence: binary.BigEndian.Uint64(data[8:16]), Payload: data[headerSize:n]}
	for _, fd := range received {
		packet.Files = append(packet.Files, os.NewFile(uintptr(fd), "untrusted-control-input"))
	}
	return packet, nil
}
