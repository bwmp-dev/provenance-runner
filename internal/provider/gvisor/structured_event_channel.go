package gvisor

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

const structuredEventDrainPollInterval = time.Millisecond

type structuredEventChannel struct {
	mu            sync.Mutex
	path          string
	maximum       int64
	reader        *os.File
	keepalive     *os.File
	stop          chan struct{}
	done          chan struct{}
	content       []byte
	bufferedBytes int64
	observed      int64
	overflowed    bool
	readErr       error
	resourceBytes int64
	removed       bool
	started       bool
	finished      bool
}

type structuredEventChannelSnapshot struct {
	content       []byte
	maximum       int64
	bufferedBytes int64
	observedBytes int64
	overflowed    bool
	readErr       error
	resourceBytes int64
	removed       bool
}

func createStructuredEventChannel(path string, maximum int64) (*structuredEventChannel, error) {
	if err := makeHostFIFO(path, 0o600); err != nil {
		return nil, fmt.Errorf("create structured event FIFO: %w", err)
	}
	return &structuredEventChannel{path: path, maximum: maximum, content: make([]byte, 0, int(maximum))}, nil
}

func (c *structuredEventChannel) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.finished {
		return errors.New("structured event FIFO cannot be started more than once")
	}
	info, err := os.Lstat(c.path)
	if err != nil {
		c.removeLocked()
		return fmt.Errorf("inspect structured event FIFO: %w", err)
	}
	c.resourceBytes = info.Size()
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeNamedPipe == 0 {
		c.removeLocked()
		return errors.New("structured event resource is not a FIFO")
	}
	reader, keepalive, err := openHostFIFO(c.path)
	if err != nil {
		c.removeLocked()
		return fmt.Errorf("open structured event FIFO: %w", err)
	}
	// Open the trusted host endpoints while the FIFO is owner-only, then expose
	// only write permission through the sandbox bind mount. A workload cannot
	// read back or consume evidence queued for the host collector.
	if err := os.Chmod(c.path, 0o222); err != nil {
		_ = reader.Close()
		_ = keepalive.Close()
		c.removeLocked()
		return fmt.Errorf("make structured event FIFO sandbox-write-only: %w", err)
	}
	c.reader = reader
	c.keepalive = keepalive
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	c.started = true
	go c.drain()
	return nil
}

func (c *structuredEventChannel) drain() {
	defer close(c.done)
	buffer := make([]byte, 32<<10)
	for {
		read, err := readHostFIFO(c.reader, buffer)
		if read > 0 {
			c.mu.Lock()
			if c.observed > math.MaxInt64-int64(read) {
				c.observed = math.MaxInt64
			} else {
				c.observed += int64(read)
			}
			remaining := c.maximum - int64(len(c.content))
			if remaining > 0 {
				keep := int64(read)
				if keep > remaining {
					keep = remaining
				}
				c.content = append(c.content, buffer[:int(keep)]...)
			}
			if int64(read) > remaining {
				c.overflowed = true
			}
			overflowed := c.overflowed
			c.mu.Unlock()
			// Before runsc returns, keep draining and discarding overflow so the
			// workload cannot deadlock on a full pipe. Afterwards, one observed
			// overflow is sufficient to terminate deterministically even if an
			// unexpected writer remains open.
			if overflowed && c.stopping() {
				return
			}
			continue
		}
		if err == nil {
			if c.stopping() {
				return
			}
			time.Sleep(structuredEventDrainPollInterval)
			continue
		}
		if hostFIFOWouldBlock(err) {
			if c.stopping() {
				return
			}
			time.Sleep(structuredEventDrainPollInterval)
			continue
		}
		c.mu.Lock()
		c.readErr = fmt.Errorf("drain structured event FIFO: %w", err)
		c.mu.Unlock()
		return
	}
}

func (c *structuredEventChannel) stopping() bool {
	select {
	case <-c.stop:
		return true
	default:
		return false
	}
}

func (c *structuredEventChannel) finish() structuredEventChannelSnapshot {
	c.mu.Lock()
	if c.finished {
		snapshot := c.snapshotLocked()
		c.mu.Unlock()
		return snapshot
	}
	started := c.started
	stop, done := c.stop, c.done
	c.mu.Unlock()

	if started {
		close(stop)
		<-done
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reader != nil {
		if err := c.reader.Close(); err != nil && c.readErr == nil {
			c.readErr = fmt.Errorf("close structured event FIFO reader: %w", err)
		}
		c.reader = nil
	}
	if c.keepalive != nil {
		if err := c.keepalive.Close(); err != nil && c.readErr == nil {
			c.readErr = fmt.Errorf("close structured event FIFO keepalive: %w", err)
		}
		c.keepalive = nil
	}
	c.removeLocked()
	c.finished = true
	c.bufferedBytes = int64(len(c.content))
	snapshot := c.snapshotLocked()
	clear(c.content)
	c.content = nil
	return snapshot
}

func (c *structuredEventChannel) removeLocked() {
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) && c.readErr == nil {
		c.readErr = fmt.Errorf("remove structured event FIFO: %w", err)
	}
	_, err := os.Lstat(c.path)
	c.removed = errors.Is(err, os.ErrNotExist)
	if err != nil && !errors.Is(err, os.ErrNotExist) && c.readErr == nil {
		c.readErr = fmt.Errorf("verify structured event FIFO removal: %w", err)
	}
}

func (c *structuredEventChannel) snapshotLocked() structuredEventChannelSnapshot {
	return structuredEventChannelSnapshot{
		content:       append([]byte(nil), c.content...),
		maximum:       c.maximum,
		bufferedBytes: c.bufferedBytes,
		observedBytes: c.observed,
		overflowed:    c.overflowed,
		readErr:       c.readErr,
		resourceBytes: c.resourceBytes,
		removed:       c.removed,
	}
}
