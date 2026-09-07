package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
)

var errStructuredRedaction = errors.New("structured event cannot be safely sanitized")

func sanitizeString(value string, patterns *secretPatterns) (string, bool) {
	var output bytes.Buffer
	changed := false
	redactor := newSecretRedactor(patterns, func(b []byte, redacted bool) { output.Write(b); changed = changed || redacted })
	ansi := ansiStripper{emit: redactor.write}
	normalizer := utf8Normalizer{emit: ansi.write}
	normalizer.write([]byte(value))
	normalizer.finish()
	ansi.finish()
	redactor.finish()
	return output.String(), changed || output.String() != value
}

func sanitizeEvent(input EventInput, patterns *secretPatterns, maximum int64) (EventInput, error) {
	if patterns == nil || patterns.count == 0 {
		return input, nil
	}
	if _, changed := sanitizeString(input.Kind, patterns); changed {
		return EventInput{}, errStructuredRedaction
	}
	decoder := json.NewDecoder(bytes.NewReader(input.Payload))
	decoder.UseNumber()
	if !uniqueJSONKeys(decoder, 0) {
		return EventInput{}, errStructuredRedaction
	}
	decoder = json.NewDecoder(bytes.NewReader(input.Payload))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return EventInput{}, errStructuredRedaction
	}
	var visit func(any, int) (any, error)
	visit = func(value any, depth int) (any, error) {
		if depth > 128 {
			return nil, errStructuredRedaction
		}
		switch item := value.(type) {
		case string:
			result, _ := sanitizeString(item, patterns)
			return result, nil
		case []any:
			for i := range item {
				result, err := visit(item[i], depth+1)
				if err != nil {
					return nil, err
				}
				item[i] = result
			}
		case map[string]any:
			for key, child := range item {
				// Keys carry meaning: reject instead of renaming or merging keys.
				if _, changed := sanitizeString(key, patterns); changed {
					return nil, errStructuredRedaction
				}
				result, err := visit(child, depth+1)
				if err != nil {
					return nil, err
				}
				item[key] = result
			}
		}
		return value, nil
	}
	clean, err := visit(value, 0)
	if err != nil {
		return EventInput{}, err
	}
	payload, err := json.Marshal(clean)
	if err != nil || int64(len(payload)) > maximum {
		return EventInput{}, errStructuredRedaction
	}
	input.Payload = payload
	return input, nil
}

func uniqueJSONKeys(decoder *json.Decoder, depth int) bool {
	if depth > 128 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	keys := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			text, ok := key.(string)
			if !ok || keys[text] {
				return false
			}
			keys[text] = true
		}
		if !uniqueJSONKeys(decoder, depth+1) {
			return false
		}
	}
	_, err = decoder.Token()
	return err == nil
}
