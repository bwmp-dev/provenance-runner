package networkpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// kernelRulesetIdentity retains every enforcement field and rule order, while
// removing only volatile counters and remaining element TTLs. Kernel handles
// remain part of identity: recreating a budget object is not a harmless change.
// Dynamic connection-set membership is accounting state, not a renewed grant.
// The baseline is captured only after this package's sealed atomic actuation.
func kernelRulesetIdentity(raw []byte, job string) ([32]byte, error) {
	fail := func() ([32]byte, error) { return [32]byte{}, ErrActuation }
	if len(raw) == 0 || len(raw) > 65536 || !validAuthorityID(job) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := uniqueJSON(d, 0)
	if err != nil {
		return fail()
	}
	if _, err := d.Token(); err != io.EOF {
		return fail()
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 1 {
		return fail()
	}
	items, ok := root["nftables"].([]any)
	if !ok || len(items) < 5 || len(items) > 4096 {
		return fail()
	}
	connectionCount, err := connectionCountIdentity(items)
	if err != nil {
		return fail()
	}
	table := "pv_" + strings.ReplaceAll(job, "-", "")
	tables, metadata := 0, 0
	chains := map[string]bool{}
	var normalized []any
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 1 {
			return fail()
		}
		for kind, payload := range entry {
			body, ok := payload.(map[string]any)
			if !ok {
				return fail()
			}
			if kind == "metainfo" {
				metadata++
				if metadata > 1 {
					return fail()
				}
				continue
			}
			if body["family"] != "inet" {
				return fail()
			}
			if kind == "table" {
				tables++
				if tables > 1 || body["name"] != table {
					return fail()
				}
			} else if body["table"] != table {
				return fail()
			}
			switch kind {
			case "table", "rule", "limit":
			case "chain":
				name, ok := body["name"].(string)
				if !ok || chains[name] || (name != "input" && name != "output" && name != "forward") || body["policy"] != "drop" || body["type"] != "filter" || body["hook"] != name {
					return fail()
				}
				chains[name] = true
			case "counter":
				delete(body, "packets")
				delete(body, "bytes")
			case "set":
				if body["name"] == "connections" {
					if !validConnectionMembership(body["elem"], connectionCount) {
						return fail()
					}
					delete(body, "elem")
				} else {
					elements, ok := body["elem"].([]any)
					if !ok || len(elements) == 0 {
						return fail()
					}
					for _, element := range elements {
						wrapper, ok := element.(map[string]any)
						if !ok || len(wrapper) != 1 {
							return fail()
						}
						content, ok := wrapper["elem"].(map[string]any)
						if !ok || content["val"] == nil {
							return fail()
						}
						delete(content, "expires")
					}
					// nft may enumerate a set in a different order; tuples and rule
					// expressions themselves retain their exact ordered structure.
					sort.Slice(elements, func(i, j int) bool {
						a, _ := json.Marshal(elements[i])
						b, _ := json.Marshal(elements[j])
						return bytes.Compare(a, b) < 0
					})
				}
			default:
				return fail()
			}
			stripPacketCounters(body)
			normalized = append(normalized, entry)
		}
	}
	if tables != 1 || len(chains) != 3 {
		return fail()
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return fail()
	}
	return sha256.Sum256(encoded), nil
}

func connectionCountIdentity(items []any) ([]byte, error) {
	var identity []byte
	var visit func(any) error
	visit = func(value any) error {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if key == "ct count" {
					count, ok := child.(map[string]any)
					if !ok || len(count) != 2 || count["inv"] != true {
						return ErrActuation
					}
					number, ok := count["val"].(json.Number)
					if !ok {
						return ErrActuation
					}
					limit, err := strconv.ParseUint(string(number), 10, 32)
					if err != nil || limit == 0 {
						return ErrActuation
					}
					encoded, err := json.Marshal(count)
					if err != nil || (identity != nil && !bytes.Equal(identity, encoded)) {
						return ErrActuation
					}
					identity = encoded
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			if rule, exists := entry["rule"]; exists {
				if err := visit(rule); err != nil {
					return nil, err
				}
			}
		}
	}
	if identity == nil {
		return nil, ErrActuation
	}
	return identity, nil
}

func validConnectionMembership(value any, expected []byte) bool {
	if value == nil {
		return true
	}
	elements, ok := value.([]any)
	if !ok || len(elements) > 1 {
		return false
	}
	for _, element := range elements {
		wrapper, ok := element.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return false
		}
		content, ok := wrapper["elem"].(map[string]any)
		if !ok || len(content) != 2 || content["val"] != json.Number("1") {
			return false
		}
		count, err := json.Marshal(content["ct count"])
		if err != nil || !bytes.Equal(count, expected) {
			return false
		}
	}
	return true
}

func stripPacketCounters(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "counter" {
				if counter, ok := child.(map[string]any); ok {
					delete(counter, "packets")
					delete(counter, "bytes")
				}
			}
			stripPacketCounters(child)
		}
	case []any:
		for _, child := range value {
			stripPacketCounters(child)
		}
	}
}

// Reject duplicate keys and excessive nesting rather than normalizing ambiguous
// tool output into a reassuring fingerprint. Input bytes are independently bound.
func uniqueJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrActuation
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		result := map[string]any{}
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, ErrActuation
			}
			if _, exists := result[key]; exists {
				return nil, ErrActuation
			}
			value, err := uniqueJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrActuation
		}
		return result, nil
	case '[':
		var result []any
		for d.More() {
			value, err := uniqueJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrActuation
		}
		return result, nil
	default:
		return nil, ErrActuation
	}
}
