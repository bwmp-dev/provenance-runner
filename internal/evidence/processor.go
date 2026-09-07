package evidence

import (
	"bytes"
	"io"
	"sync"
	"unicode/utf8"
)

type rawProcessor struct {
	mu                                       sync.Mutex
	collector                                *Collector
	stream                                   Stream
	normalizer                               utf8Normalizer
	ansi                                     ansiStripper
	redactor                                 secretRedactor
	line                                     lineLimiter
	finished                                 bool
	prefix                                   []byte
	probe                                    []byte
	route                                    uint8
	probeMasked                              []bool
	rawMasked                                bool
	structuredLine                           lineLimiter
	structuredUnsafe, jsonString, jsonEscape bool
}

func newRawProcessor(collector *Collector, stream Stream, config Config) *rawProcessor {
	processor := &rawProcessor{collector: collector, stream: stream}
	maximumLineBytes := config.MaxLineBytes
	if stream == StreamStdout && config.StructuredLinePrefix != "" {
		structuredMaximum := int64(len(config.StructuredLinePrefix)) + config.MaxEventBytes
		if structuredMaximum > maximumLineBytes {
			maximumLineBytes = structuredMaximum
		}
	}
	processor.line = lineLimiter{
		maximum: maximumLineBytes,
		emit: func(line []byte, truncated, partial, redacted bool) {
			collector.emitRawLine(stream, line, truncated, partial, redacted, false)
		},
	}
	processor.structuredLine = lineLimiter{maximum: maximumLineBytes, emit: func(line []byte, truncated, partial, redacted bool) {
		if processor.structuredUnsafe {
			collector.mu.Lock()
			collector.setStructuredEventError("structured event cannot be safely sanitized")
			collector.mu.Unlock()
		} else {
			collector.emitRawLine(stream, line, truncated, partial, redacted, true)
		}
	}}
	processor.redactor = newSecretRedactor(config.patterns, func([]byte, bool) {})
	processor.redactor.observe = processor.routeMatched
	if stream == StreamStdout {
		processor.prefix = []byte(config.StructuredLinePrefix)
	}
	processor.ansi.emit = processor.redactor.write
	processor.normalizer.emit = processor.ansi.write
	return processor
}

func (p *rawProcessor) Write(content []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return len(content), nil
	}
	p.collector.observeRawBytes(int64(len(content)))
	p.normalizer.write(content)
	return len(content), nil
}

func (p *rawProcessor) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.normalizer.finish()
	p.ansi.finish()
	p.redactor.finish()
	for i, value := range p.probe {
		p.emitMatchedRaw(value, p.probeMasked[i])
	}
	p.probe = nil
	p.probeMasked = nil
	p.structuredLine.finish()
	p.line.finish()
	p.finished = true
}

// Route original bytes only AFTER the whole-stream matcher has established
// their masking status. Never reset its state at JSON or newline boundaries.
func (p *rawProcessor) routeMatched(content []byte, masked bool) {
	for _, value := range content {
		if len(p.prefix) == 0 {
			p.emitMatchedRaw(value, masked)
			continue
		}
		if p.route == 0 {
			p.probe = append(p.probe, value)
			p.probeMasked = append(p.probeMasked, masked)
			if !bytes.HasPrefix(p.prefix, p.probe) {
				p.route = 1
				for i, b := range p.probe {
					p.emitMatchedRaw(b, p.probeMasked[i])
				}
				p.probe = p.probe[:0]
				p.probeMasked = p.probeMasked[:0]
			} else if len(p.probe) == len(p.prefix) {
				p.route = 2
				p.structuredUnsafe = false
				p.jsonString = false
				p.jsonEscape = false
				for _, hit := range p.probeMasked {
					p.structuredUnsafe = p.structuredUnsafe || hit
					if !hit {
						p.rawMasked = false
					}
				}
				p.structuredLine.write(p.probe, false)
				p.probe = p.probe[:0]
				p.probeMasked = p.probeMasked[:0]
			}
		} else if p.route == 1 {
			p.emitMatchedRaw(value, masked)
		} else {
			if !masked {
				p.rawMasked = false
			}
			// A match touching JSON syntax or a scalar is not safely
			// replaceable. String bodies are sanitized after JSON decoding.
			inBody := p.jsonString && (p.jsonEscape || value != '"')
			if masked && !inBody {
				p.structuredUnsafe = true
			}
			if p.jsonString {
				if p.jsonEscape {
					p.jsonEscape = false
				} else if value == '\\' {
					p.jsonEscape = true
				} else if value == '"' {
					p.jsonString = false
				}
			} else if value == '"' {
				p.jsonString = true
			}
			p.structuredLine.write([]byte{value}, false)
		}
		if value == '\n' {
			p.route = 0
		}
	}
}

func (p *rawProcessor) emitMatchedRaw(value byte, masked bool) {
	if masked {
		if !p.rawMasked {
			p.line.write([]byte(RedactionMarker), true)
		}
	} else {
		p.line.write([]byte{value}, false)
	}
	p.rawMasked = masked
}

type utf8Normalizer struct {
	pending []byte
	emit    func([]byte)
}

func (n *utf8Normalizer) write(content []byte) {
	data := make([]byte, 0, len(n.pending)+len(content))
	data = append(data, n.pending...)
	data = append(data, content...)
	n.pending = n.pending[:0]

	for len(data) > 0 {
		if !utf8.FullRune(data) {
			n.pending = append(n.pending, data...)
			return
		}
		runeValue, size := utf8.DecodeRune(data)
		if runeValue == utf8.RuneError && size == 1 {
			n.emit([]byte("\uFFFD"))
			data = data[invalidSequenceSize(data):]
			continue
		}
		n.emit(data[:size])
		data = data[size:]
	}
}

func invalidSequenceSize(data []byte) int {
	expected := 1
	switch {
	case data[0] >= 0xc2 && data[0] <= 0xdf:
		expected = 2
	case data[0] >= 0xe0 && data[0] <= 0xef:
		expected = 3
	case data[0] >= 0xf0 && data[0] <= 0xf4:
		expected = 4
	}
	size := 1
	for size < expected && size < len(data) && data[size]&0xc0 == 0x80 {
		size++
	}
	return size
}

func (n *utf8Normalizer) finish() {
	if len(n.pending) > 0 {
		n.emit([]byte("\uFFFD"))
		n.pending = n.pending[:0]
	}
}

type ansiState uint8

const (
	ansiText ansiState = iota
	ansiEscape
	ansiCSI
	ansiOSC
	ansiOSCEscape
)

type ansiStripper struct {
	state          ansiState
	sequenceLength int
	emit           func([]byte)
}

func (s *ansiStripper) write(content []byte) {
	for _, value := range content {
		switch s.state {
		case ansiText:
			if value == 0x1b {
				s.state = ansiEscape
				s.sequenceLength = 0
				continue
			}
			s.emit([]byte{value})
		case ansiEscape:
			switch value {
			case '[':
				s.state = ansiCSI
			case ']':
				s.state = ansiOSC
			case '7', '8', '=', '>':
				s.state = ansiText
			default:
				s.state = ansiText
				if value == '\n' || value == '\r' {
					s.emit([]byte{value})
				}
			}
		case ansiCSI:
			s.sequenceLength++
			if value == '\n' || value == '\r' {
				s.state = ansiText
				s.emit([]byte{value})
				continue
			}
			if value >= 0x40 && value <= 0x7e {
				s.state = ansiText
			} else if s.sequenceLength >= 256 {
				s.state = ansiText
			}
		case ansiOSC:
			s.sequenceLength++
			switch value {
			case 0x07:
				s.state = ansiText
			case 0x1b:
				s.state = ansiOSCEscape
			case '\n', '\r':
				s.state = ansiText
				s.emit([]byte{value})
			default:
				if s.sequenceLength >= 256 {
					s.state = ansiText
				}
			}
		case ansiOSCEscape:
			if value == '\\' {
				s.state = ansiText
			} else {
				s.state = ansiOSC
			}
		}
	}
}

func (s *ansiStripper) finish() {
	s.state = ansiText
}

type lineLimiter struct {
	maximum    int64
	line       []byte
	discarding bool
	redacted   bool
	emit       func([]byte, bool, bool, bool)
}

func (l *lineLimiter) write(content []byte, redacted bool) {
	if redacted {
		l.redacted = true
	}
	for _, value := range content {
		if value == '\n' {
			l.flush(true)
			continue
		}
		if l.discarding {
			continue
		}
		if int64(len(l.line)) >= l.maximum {
			l.discarding = true
			continue
		}
		l.line = append(l.line, value)
	}
}

func (l *lineLimiter) finish() {
	if len(l.line) > 0 || l.discarding {
		l.flush(false)
	}
}

func (l *lineLimiter) flush(newline bool) {
	line := l.line
	for len(line) > 0 && !utf8.Valid(line) {
		line = line[:len(line)-1]
	}
	output := make([]byte, 0, len(line)+len(LineTruncationMarker)+1)
	output = append(output, line...)
	if l.discarding {
		output = append(output, LineTruncationMarker...)
	}
	if newline {
		output = append(output, '\n')
	}
	l.emit(output, l.discarding, !newline, l.redacted)
	l.line = l.line[:0]
	l.discarding = false
	l.redacted = false
}

var _ io.Writer = (*rawProcessor)(nil)
