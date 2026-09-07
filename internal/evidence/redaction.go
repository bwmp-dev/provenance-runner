package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

const maximumPatterns = 512
const maximumPatternBytes = 768 << 10
const maximumHoldback = 128 << 10

// Sparse Aho-Corasick automaton: linear storage in pattern bytes, rather than
// a 256-entry transition table for every prefix. Immutable after compilation.
type matchNode struct{ edge, failure, longest int }
type matchEdge struct {
	value        byte
	target, next int
}
type secretPatterns struct {
	nodes                []matchNode
	edges                []matchEdge
	maximum, count, size int
}

func compileSecrets(secrets []string) (*secretPatterns, error) {
	set := make(map[string]struct{})
	raw := make(map[string]struct{})
	for _, secret := range secrets {
		if _, exists := raw[secret]; exists {
			continue
		}
		raw[secret] = struct{}{}
		var normalized bytes.Buffer
		ansi := ansiStripper{emit: func(b []byte) { normalized.Write(b) }}
		norm := utf8Normalizer{emit: ansi.write}
		norm.write([]byte(secret))
		norm.finish()
		ansi.finish()
		variants := []string{secret, normalized.String(),
			base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)),
			base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)),
			hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret)))}
		for _, variant := range variants {
			if variant != "" {
				set[variant] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(set))
	p := &secretPatterns{nodes: []matchNode{{edge: -1}}, count: len(set)}
	for key := range set {
		keys = append(keys, key)
		p.size += len(key)
		p.maximum = max(p.maximum, len(key))
	}
	if p.count > maximumPatterns || p.size > maximumPatternBytes || p.maximum > maximumHoldback {
		return nil, errors.New("redaction expansion exceeds supported limits")
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := 0
		for i := range len(key) {
			next := p.transition(state, key[i])
			if next == 0 {
				next = len(p.nodes)
				p.nodes = append(p.nodes, matchNode{edge: -1})
				p.edges = append(p.edges, matchEdge{key[i], next, p.nodes[state].edge})
				p.nodes[state].edge = len(p.edges) - 1
			}
			state = next
		}
		p.nodes[state].longest = len(key)
	}
	queue := make([]int, 0, len(p.nodes))
	for e := p.nodes[0].edge; e >= 0; e = p.edges[e].next {
		queue = append(queue, p.edges[e].target)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for e := p.nodes[state].edge; e >= 0; e = p.edges[e].next {
			edge := p.edges[e]
			fallback := p.nodes[state].failure
			for fallback != 0 && p.transition(fallback, edge.value) == 0 {
				fallback = p.nodes[fallback].failure
			}
			failure := p.transition(fallback, edge.value)
			p.nodes[edge.target].failure = failure
			p.nodes[edge.target].longest = max(p.nodes[edge.target].longest, p.nodes[failure].longest)
			queue = append(queue, edge.target)
		}
	}
	return p, nil
}

func (p *secretPatterns) transition(state int, value byte) int {
	for e := p.nodes[state].edge; e >= 0; e = p.edges[e].next {
		if p.edges[e].value == value {
			return p.edges[e].target
		}
	}
	return 0
}

type matchInterval struct{ start, end int64 }
type secretRedactor struct {
	patterns      *secretPatterns
	pending       []byte
	intervals     []matchInterval
	state         int
	read, written int64
	masked        bool
	emit          func([]byte, bool)
	observe       func([]byte, bool)
}

func newSecretRedactor(patterns *secretPatterns, emit func([]byte, bool)) secretRedactor {
	r := secretRedactor{patterns: patterns, emit: emit}
	if patterns != nil && patterns.maximum > 0 {
		r.pending = make([]byte, patterns.maximum)
	}
	return r
}

func (r *secretRedactor) write(content []byte) {
	if len(r.pending) == 0 {
		if r.observe != nil {
			r.observe(content, false)
			return
		}
		r.emit(content, false)
		return
	}
	for _, value := range content {
		p := r.patterns
		for r.state != 0 && p.transition(r.state, value) == 0 {
			r.state = p.nodes[r.state].failure
		}
		r.state = p.transition(r.state, value)
		r.pending[r.read%int64(len(r.pending))] = value
		r.read++
		if length := p.nodes[r.state].longest; length != 0 {
			interval := matchInterval{r.read - int64(length), r.read}
			for len(r.intervals) > 0 && r.intervals[len(r.intervals)-1].end >= interval.start {
				interval.start = min(interval.start, r.intervals[len(r.intervals)-1].start)
				r.intervals = r.intervals[:len(r.intervals)-1]
			}
			r.intervals = append(r.intervals, interval)
		}
		if r.read-r.written >= int64(len(r.pending)) {
			r.emitNext()
		}
	}
}

func (r *secretRedactor) finish() {
	for r.written < r.read {
		r.emitNext()
	}
}

func (r *secretRedactor) emitNext() {
	for len(r.intervals) > 0 && r.intervals[0].end <= r.written {
		r.intervals = r.intervals[1:]
	}
	masked := len(r.intervals) > 0 && r.intervals[0].start <= r.written
	if r.observe != nil {
		pos := r.written % int64(len(r.pending))
		r.observe(r.pending[pos:pos+1], masked)
		r.written++
		return
	}
	if masked {
		if !r.masked {
			r.emit([]byte(RedactionMarker), true)
		}
	} else {
		pos := r.written % int64(len(r.pending))
		r.emit(r.pending[pos:pos+1], false)
	}
	r.masked = masked
	r.written++
}
