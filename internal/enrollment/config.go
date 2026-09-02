package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	ConfigSchemaVersion = "provenance.runner-enrollment/v1alpha1"
	maximumConfigBytes  = 64 << 10
)

type Config struct {
	SchemaVersion         string `json:"schemaVersion"`
	APIBaseURL            string `json:"apiBaseUrl"`
	ConnectConfigFile     string `json:"connectConfigFile"`
	RegistrationTokenFile string `json:"registrationTokenFile"`
	CredentialTTLSeconds  int    `json:"credentialTtlSeconds"`
}

func LoadConfig(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, errors.New("resolve enrollment configuration failed")
	}
	path = absolute
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return Config{}, errors.New("enrollment configuration must be a regular file and not a symbolic link")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("open enrollment configuration failed")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return Config{}, errors.New("enrollment configuration changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumConfigBytes+1))
	if err != nil || len(data) > maximumConfigBytes {
		return Config{}, errors.New("read enrollment configuration failed")
	}
	if err := rejectDuplicateMembers(data); err != nil {
		return Config{}, errors.New("decode enrollment configuration failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("decode enrollment configuration failed")
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, err
	}
	if config.SchemaVersion != ConfigSchemaVersion {
		return Config{}, fmt.Errorf("schemaVersion must be %q", ConfigSchemaVersion)
	}
	baseURL, err := url.Parse(config.APIBaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.Path != "" {
		return Config{}, errors.New("apiBaseUrl must be an HTTPS origin without a path, query, fragment, or user information")
	}
	if strings.TrimSpace(config.ConnectConfigFile) == "" || strings.TrimSpace(config.RegistrationTokenFile) == "" || len(config.ConnectConfigFile) > 4096 || len(config.RegistrationTokenFile) > 4096 {
		return Config{}, errors.New("connectConfigFile and registrationTokenFile are required bounded paths")
	}
	if config.CredentialTTLSeconds < 300 || config.CredentialTTLSeconds > 3600 {
		return Config{}, errors.New("credentialTtlSeconds must be between 300 and 3600")
	}
	baseDirectory := filepath.Dir(path)
	if !filepath.IsAbs(config.ConnectConfigFile) {
		config.ConnectConfigFile = filepath.Join(baseDirectory, config.ConnectConfigFile)
	}
	if !filepath.IsAbs(config.RegistrationTokenFile) {
		config.RegistrationTokenFile = filepath.Join(baseDirectory, config.RegistrationTokenFile)
	}
	return config, nil
}

func rejectDuplicateMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON member")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("enrollment configuration has trailing data")
	}
	return nil
}
