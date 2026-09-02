package runneridentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion        = "provenance.runner-identity/v1alpha1"
	MaximumDocumentBytes = 16 << 10
	PhasePrepared        = "prepared"
	PhaseReceived        = "response_received"
	PhaseActive          = "active"
	PhaseTerminal        = "terminal"
)

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var idempotencyKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
var sha256Text = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Document struct {
	SchemaVersion        string    `json:"schemaVersion"`
	Phase                string    `json:"phase"`
	OrganizationID       string    `json:"organizationId"`
	RunnerID             string    `json:"runnerId"`
	PrivateKeySeed       string    `json:"privateKeySeed,omitempty"`
	PublicKey            string    `json:"publicKey,omitempty"`
	PublicKeyFingerprint string    `json:"publicKeyFingerprint,omitempty"`
	TokenSHA256          string    `json:"registrationTokenSha256,omitempty"`
	IdempotencyKey       string    `json:"idempotencyKey,omitempty"`
	CredentialTTLSeconds int       `json:"credentialTtlSeconds,omitempty"`
	Response             *Response `json:"response,omitempty"`
	Terminal             *Terminal `json:"terminal,omitempty"`
}

type Response struct {
	CredentialID     string    `json:"credentialId"`
	Credential       string    `json:"credential"`
	CredentialSHA256 string    `json:"credentialSha256"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type Terminal struct {
	Code string `json:"code"`
}

func NewPrepared(organizationID, runnerID string, tokenSHA256 [sha256.Size]byte, key string, ttl int, random io.Reader) (Document, error) {
	if random == nil {
		return Document{}, errors.New("identity randomness is unavailable")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return Document{}, errors.New("generate runner identity failed")
	}
	seed := privateKey.Seed()
	clear(privateKey)
	document := Document{
		SchemaVersion: SchemaVersion, Phase: PhasePrepared, OrganizationID: organizationID, RunnerID: runnerID,
		PrivateKeySeed: base64.RawURLEncoding.EncodeToString(seed), PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(sha256Digest(publicKey)), TokenSHA256: hex.EncodeToString(tokenSHA256[:]),
		IdempotencyKey: key, CredentialTTLSeconds: ttl,
	}
	clear(seed)
	clear(publicKey)
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func Decode(data []byte) (Document, error) {
	if err := rejectDuplicateMembers(data); err != nil {
		return Document{}, errors.New("decode runner identity failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, errors.New("decode runner identity failed")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("runner identity has trailing data")
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
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

func (document Document) Encode() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("encode runner identity failed")
	}
	return data, nil
}

func (document Document) Validate() error {
	if document.SchemaVersion != SchemaVersion || !canonicalUUID.MatchString(document.OrganizationID) || !canonicalUUID.MatchString(document.RunnerID) {
		return errors.New("runner identity metadata is invalid")
	}
	switch document.Phase {
	case PhasePrepared, PhaseReceived, PhaseActive:
		seed, publicKey, ok := document.keyMaterial()
		clear(seed)
		clear(publicKey)
		if !ok {
			return errors.New("runner identity key material is invalid")
		}
	case PhaseTerminal:
		if document.PrivateKeySeed != "" || document.PublicKey != "" || document.PublicKeyFingerprint != "" ||
			document.Response != nil || document.Terminal == nil || !validCode(document.Terminal.Code) ||
			!sha256Text.MatchString(document.TokenSHA256) || !idempotencyKey.MatchString(document.IdempotencyKey) ||
			document.CredentialTTLSeconds != 0 {
			return errors.New("terminal runner identity state is invalid")
		}
	default:
		return errors.New("runner identity phase is invalid")
	}
	if document.Phase == PhasePrepared || document.Phase == PhaseReceived {
		if !sha256Text.MatchString(document.TokenSHA256) || !idempotencyKey.MatchString(document.IdempotencyKey) || document.CredentialTTLSeconds < 300 || document.CredentialTTLSeconds > 3600 || document.Terminal != nil {
			return errors.New("runner enrollment attempt identity is invalid")
		}
	}
	if document.Phase == PhasePrepared && document.Response != nil {
		return errors.New("prepared runner identity contains a response")
	}
	if document.Phase == PhaseReceived {
		if !validResponse(document.Response, document.CredentialTTLSeconds) {
			return errors.New("runner enrollment response state is invalid")
		}
	}
	if document.Phase == PhaseActive {
		if document.TokenSHA256 != "" || document.IdempotencyKey != "" || document.CredentialTTLSeconds != 0 || document.Terminal != nil || document.Response == nil || document.Response.Credential != "" || !validActiveResponse(document.Response) {
			return errors.New("active runner identity state is invalid")
		}
	}
	return nil
}

func (document Document) Sign(message []byte) ([]byte, error) {
	seed, _, ok := document.keyMaterial()
	if !ok || document.Phase == PhaseTerminal {
		clear(seed)
		return nil, errors.New("runner identity cannot sign enrollment")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	signature := ed25519.Sign(privateKey, message)
	clear(privateKey)
	return signature, nil
}

func (document Document) Received(response Response) (Document, error) {
	document.Phase = PhaseReceived
	document.Response = &response
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func (document Document) Active() (Document, error) {
	if document.Phase != PhaseReceived || document.Response == nil {
		return Document{}, errors.New("runner identity has no durable enrollment response")
	}
	document.Phase = PhaseActive
	document.TokenSHA256 = ""
	document.IdempotencyKey = ""
	document.CredentialTTLSeconds = 0
	document.Response.Credential = ""
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func (document Document) Terminated(code string) (Document, error) {
	terminal := Document{
		SchemaVersion: SchemaVersion, Phase: PhaseTerminal, OrganizationID: document.OrganizationID, RunnerID: document.RunnerID,
		TokenSHA256: document.TokenSHA256, IdempotencyKey: document.IdempotencyKey, Terminal: &Terminal{Code: code},
	}
	if err := terminal.Validate(); err != nil {
		return Document{}, err
	}
	return terminal, nil
}

func (document Document) Seed() ([]byte, error) {
	seed, _, ok := document.keyMaterial()
	if !ok || document.Phase != PhaseActive {
		clear(seed)
		return nil, errors.New("runner identity is not active")
	}
	return seed, nil
}

func (document Document) MatchesCredential(credential []byte) bool {
	if document.Phase != PhaseActive || document.Response == nil || len(credential) == 0 {
		return false
	}
	actual := []byte(hex.EncodeToString(sha256Digest(credential)))
	expected := []byte(document.Response.CredentialSHA256)
	matched := subtle.ConstantTimeCompare(actual, expected) == 1
	clear(actual)
	clear(expected)
	return matched
}

func (document Document) keyMaterial() ([]byte, []byte, bool) {
	seed, err := base64.RawURLEncoding.DecodeString(document.PrivateKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize || base64.RawURLEncoding.EncodeToString(seed) != document.PrivateKeySeed {
		clear(seed)
		return nil, nil, false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(document.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != document.PublicKey {
		clear(seed)
		clear(publicKey)
		return nil, nil, false
	}
	derived := ed25519.NewKeyFromSeed(seed)
	valid := bytes.Equal(derived[ed25519.SeedSize:], publicKey) && document.PublicKeyFingerprint == "sha256:"+hex.EncodeToString(sha256Digest(publicKey))
	clear(derived)
	return seed, publicKey, valid
}

func validResponse(response *Response, requestedTTL int) bool {
	if !validActiveResponse(response) || !validCredential(response.Credential) || response.ExpiresAt.Sub(response.IssuedAt) > time.Duration(requestedTTL)*time.Second {
		return false
	}
	actual := []byte(hex.EncodeToString(sha256Digest([]byte(response.Credential))))
	expected := []byte(response.CredentialSHA256)
	matched := subtle.ConstantTimeCompare(actual, expected) == 1
	clear(actual)
	clear(expected)
	return matched
}

func validActiveResponse(response *Response) bool {
	return response != nil && canonicalUUID.MatchString(response.CredentialID) && sha256Text.MatchString(response.CredentialSHA256) &&
		!response.IssuedAt.IsZero() && response.ExpiresAt.After(response.IssuedAt) && response.ExpiresAt.Sub(response.IssuedAt) >= 300*time.Second && response.ExpiresAt.Sub(response.IssuedAt) <= time.Hour
}

func validCredential(value string) bool {
	if len(value) != 50 || !strings.HasPrefix(value, "prc_v1_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value[len("prc_v1_"):])
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return false
	}
	valid := base64.RawURLEncoding.EncodeToString(decoded) == value[len("prc_v1_"):]
	clear(decoded)
	return valid
}

func validCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func sha256Digest(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func ValidateCanonicalUUID(value string) error {
	if !canonicalUUID.MatchString(value) {
		return errors.New("identifier must be a canonical lowercase UUID")
	}
	return nil
}
