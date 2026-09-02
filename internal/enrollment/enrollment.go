package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/gatewayclient"
	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
)

const (
	maximumResponseBytes = 64 << 10
	maximumTokenBytes    = 4096
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Options struct {
	HTTPClient HTTPDoer
	Random     io.Reader
}

type Error struct {
	Code      string
	Retryable bool
	message   string
}

func (failure *Error) Error() string { return failure.message }

func Run(ctx context.Context, configPath string, options Options) error {
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	connect, err := gatewayclient.LoadPublicConfig(config.ConnectConfigFile)
	if err != nil {
		return fmt.Errorf("load connect configuration: %w", err)
	}
	if connect.ExpectedScope.Kind != gatewayclient.ScopeOrganization || connect.IdentityKeyFile == "" {
		return errors.New("enrollment requires an organization-scoped connect configuration with identityKeyFile")
	}
	if samePath(connect.IdentityKeyFile, connect.CredentialFile) || samePath(connect.IdentityKeyFile, config.RegistrationTokenFile) || samePath(connect.CredentialFile, config.RegistrationTokenFile) {
		return errors.New("identity, credential, and registration token files must use distinct paths")
	}
	store, err := openStore(connect.IdentityKeyFile, connect.CredentialFile, config.RegistrationTokenFile)
	if err != nil {
		return err
	}
	defer store.Close()
	token, err := store.ReadToken()
	if err != nil {
		return err
	}
	defer clear(token)
	tokenHash := sha256.Sum256(token)
	if !validRegistrationToken(token) {
		return errors.New("registration token is invalid")
	}

	document, exists, err := store.ReadIdentity()
	if err != nil {
		return err
	}
	if exists && document.Phase == runneridentity.PhaseActive {
		return errors.New("runner identity is already active; the supplied registration token was left untouched")
	}
	if !exists || (document.Phase != runneridentity.PhaseReceived && document.Phase != runneridentity.PhaseActive) {
		credentialExists, credentialErr := store.CredentialExists()
		if credentialErr != nil {
			return credentialErr
		}
		if credentialExists {
			return errors.New("credential file already exists; enrollment will not replace a usable credential")
		}
	}
	if exists && document.Phase == runneridentity.PhaseReceived {
		if document.TokenSHA256 != hex.EncodeToString(tokenHash[:]) {
			return errors.New("registration token does not match the recoverable enrollment")
		}
		return finish(store, document, tokenHash)
	}
	if !exists || (document.Phase == runneridentity.PhaseTerminal && document.TokenSHA256 != hex.EncodeToString(tokenHash[:])) {
		idempotency, keyErr := newIdempotencyKey(options.Random)
		if keyErr != nil {
			return keyErr
		}
		document, err = runneridentity.NewPrepared(connect.ExpectedScope.OrganizationID, strings.ToLower(connect.RunnerID), tokenHash, idempotency, config.CredentialTTLSeconds, options.Random)
		if err != nil {
			return err
		}
		if err := store.WriteIdentity(document); err != nil {
			return err
		}
	} else if document.Phase == runneridentity.PhaseTerminal {
		return terminalFailure(document.Terminal.Code)
	} else if document.Phase != runneridentity.PhasePrepared || document.TokenSHA256 != hex.EncodeToString(tokenHash[:]) ||
		document.RunnerID != strings.ToLower(connect.RunnerID) || document.OrganizationID != strings.ToLower(connect.ExpectedScope.OrganizationID) {
		return errors.New("recoverable enrollment does not match the connect configuration or registration token")
	}

	response, failure := redeem(ctx, options.HTTPClient, config.APIBaseURL, token, document)
	if failure != nil {
		if isTerminal(failure.Code) {
			terminal, terminalErr := document.Terminated(failure.Code)
			if terminalErr != nil {
				return terminalErr
			}
			if err := store.WriteIdentity(terminal); err != nil {
				return errors.New("persist terminal enrollment state failed")
			}
			if err := store.RemoveToken(tokenHash); err != nil {
				return errors.New("clear terminal registration token failed")
			}
		}
		return failure
	}
	received, err := document.Received(response)
	clearString(&response.Credential)
	if err != nil {
		return errors.New("registration response is invalid")
	}
	if err := store.WriteIdentity(received); err != nil {
		return errors.New("persist registration response failed")
	}
	return finish(store, received, tokenHash)
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func finish(store enrollmentStore, document runneridentity.Document, tokenHash [sha256.Size]byte) error {
	credential := []byte(document.Response.Credential)
	defer clear(credential)
	if err := store.InstallCredential(credential); err != nil {
		return err
	}
	active, err := document.Active()
	if err != nil {
		return err
	}
	if err := store.WriteIdentity(active); err != nil {
		return errors.New("persist active runner identity failed")
	}
	if err := store.RemoveToken(tokenHash); err != nil {
		return errors.New("clear consumed registration token failed")
	}
	return nil
}

type redeemRequest struct {
	PublicKey            string `json:"publicKey"`
	PossessionProof      string `json:"possessionProof"`
	CredentialTTLSeconds int    `json:"credentialTtlSeconds"`
}

type redeemResponse struct {
	RunnerID             string    `json:"runnerId"`
	OrganizationID       string    `json:"organizationId"`
	CredentialID         string    `json:"credentialId"`
	Credential           string    `json:"credential"`
	IssuedAt             time.Time `json:"issuedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	PublicKeyFingerprint string    `json:"publicKeyFingerprint"`
}

func redeem(ctx context.Context, client HTTPDoer, baseURL string, token []byte, document runneridentity.Document) (runneridentity.Response, *Error) {
	message := []byte("provenance.runner.registration.v1\norganization_id:" + document.OrganizationID + "\nrunner_id:" + document.RunnerID + "\nregistration_token_sha256:" + document.TokenSHA256 + "\npublic_key_base64url:" + document.PublicKey + "\n")
	signature, err := document.Sign(message)
	clear(message)
	if err != nil {
		return runneridentity.Response{}, &Error{Code: "local_identity_invalid", message: "local enrollment identity is invalid"}
	}
	payload, err := json.Marshal(redeemRequest{PublicKey: document.PublicKey, PossessionProof: base64.RawURLEncoding.EncodeToString(signature), CredentialTTLSeconds: document.CredentialTTLSeconds})
	clear(signature)
	if err != nil {
		return runneridentity.Response{}, &Error{Code: "local_request_invalid", message: "construct registration request failed"}
	}
	endpoint := strings.TrimSuffix(baseURL, "/") + "/v1/runners/" + url.PathEscape(document.RunnerID) + "/registration-redemptions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		clear(payload)
		return runneridentity.Response{}, &Error{Code: "request_unavailable", Retryable: true, message: "construct registration request failed"}
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Idempotency-Key", document.IdempotencyKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	clear(payload)
	request.Header.Del("Authorization")
	if err != nil {
		if ctx.Err() != nil {
			return runneridentity.Response{}, &Error{Code: "request_cancelled", message: "registration request was cancelled"}
		}
		return runneridentity.Response{}, &Error{Code: "transport_ambiguous", Retryable: true, message: "registration response was not received; rerun enrollment with the same token"}
	}
	if response == nil || response.Body == nil {
		return runneridentity.Response{}, &Error{Code: "response_unavailable", Retryable: true, message: "registration response could not be read; rerun enrollment with the same token"}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if readErr != nil || len(body) > maximumResponseBytes {
		clear(body)
		return runneridentity.Response{}, &Error{Code: "response_unavailable", Retryable: true, message: "registration response could not be read; rerun enrollment with the same token"}
	}
	defer clear(body)
	if response.StatusCode == http.StatusCreated {
		if !hasMediaType(response.Header, "application/json") {
			return runneridentity.Response{}, &Error{Code: "response_invalid", message: "registration response did not use the released JSON representation"}
		}
		var result redeemResponse
		if err := decodeExact(body, &result); err != nil || result.RunnerID != document.RunnerID || result.OrganizationID != document.OrganizationID || result.PublicKeyFingerprint != document.PublicKeyFingerprint {
			clearString(&result.Credential)
			return runneridentity.Response{}, &Error{Code: "response_invalid", message: "registration response did not match the requested runner identity"}
		}
		credentialDigest := sha256.Sum256([]byte(result.Credential))
		return runneridentity.Response{CredentialID: result.CredentialID, Credential: result.Credential, CredentialSHA256: hex.EncodeToString(credentialDigest[:]), IssuedAt: result.IssuedAt, ExpiresAt: result.ExpiresAt}, nil
	}
	var problem struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Code   string `json:"code"`
	}
	if !hasMediaType(response.Header, "application/problem+json") {
		return runneridentity.Response{}, &Error{Code: "registration_failed", Retryable: response.StatusCode >= 500, message: "registration authority returned a bounded failure"}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := rejectDuplicateMembers(body); err != nil || decoder.Decode(&problem) != nil || problem.Type == "" || problem.Title == "" || problem.Status != response.StatusCode || !validProblemCode(problem.Code) || !problemStatusMatches(response.StatusCode, problem.Code) ||
		(response.StatusCode == http.StatusUnauthorized && response.Header.Get("WWW-Authenticate") != `Bearer realm="runner-registration", error="invalid_token"`) {
		return runneridentity.Response{}, &Error{Code: "registration_failed", Retryable: response.StatusCode >= 500, message: "registration authority returned a bounded failure"}
	}
	retryable := response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests
	return runneridentity.Response{}, &Error{Code: problem.Code, Retryable: retryable, message: problemMessage(problem.Code, retryable)}
}

func hasMediaType(header http.Header, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	return err == nil && mediaType == expected
}

func problemStatusMatches(status int, code string) bool {
	switch status {
	case http.StatusUnauthorized:
		return code == "registration_token_invalid"
	case http.StatusConflict:
		return code == "idempotency_key_conflict" || code == "credential_not_replayable" || code == "registration_token_consumed" || code == "runner_key_conflict"
	case http.StatusGone:
		return code == "registration_token_expired"
	case http.StatusUnprocessableEntity:
		return code == "registration_proof_invalid"
	default:
		return status >= 500 || status == http.StatusTooManyRequests
	}
}

func decodeExact(data []byte, target any) error {
	if err := rejectDuplicateMembers(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("response has trailing data")
	}
	return nil
}

func newIdempotencyKey(random io.Reader) (string, error) {
	var value [24]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", errors.New("generate enrollment attempt identity failed")
	}
	return "enroll:" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func validRegistrationToken(token []byte) bool {
	if len(token) != 50 || !bytes.HasPrefix(token, []byte("prr_v1_")) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(token[7:]))
	valid := err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == string(token[7:])
	clear(decoded)
	return valid
}

func validProblemCode(code string) bool {
	if len(code) < 1 || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func isTerminal(code string) bool {
	switch code {
	case "credential_not_replayable", "registration_token_consumed", "registration_token_expired", "registration_token_invalid", "registration_proof_invalid", "runner_key_conflict", "idempotency_key_conflict":
		return true
	default:
		return false
	}
}

func terminalFailure(code string) error {
	return &Error{Code: code, message: problemMessage(code, false)}
}

func problemMessage(code string, retryable bool) string {
	if retryable {
		return "registration authority is temporarily unavailable; retry enrollment with the same token"
	}
	switch code {
	case "credential_not_replayable", "registration_token_consumed":
		return "registration cannot be retried; issue a new one-time registration token and replace the enrollment token file"
	default:
		return "registration was rejected; issue a new one-time registration token before retrying"
	}
}

func clearString(value *string) { *value = "" }
