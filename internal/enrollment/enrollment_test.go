//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/gatewayclient"
	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
)

const (
	testOrganizationID = "00000000-0000-0000-0000-000000000011"
	testRunnerID       = "50000000-0000-0000-0000-000000000011"
	testToken          = "prr_v1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

type testPaths struct {
	directory, enrollment, connect, identity, credential, token string
}

func setupEnrollment(t *testing.T, apiURL, token string) testPaths {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := testPaths{directory: directory, enrollment: filepath.Join(directory, "enrollment.json"), connect: filepath.Join(directory, "connect.json"), identity: filepath.Join(directory, "identity.json"), credential: filepath.Join(directory, "credential"), token: filepath.Join(directory, "registration-token")}
	connect := fmt.Sprintf(`{"schemaVersion":%q,"gatewayAddress":"gateway.example:443","runnerId":%q,"instanceId":"instance-1","credentialFile":"credential","identityKeyFile":"identity.json","expectedScope":{"kind":"organization","organizationId":%q},"resources":{"cpuMillis":1000,"memoryBytes":1073741824,"diskBytes":2147483648,"processCount":64}}`, gatewayclient.ConfigSchemaVersion, testRunnerID, testOrganizationID)
	enrollment := fmt.Sprintf(`{"schemaVersion":%q,"apiBaseUrl":%q,"connectConfigFile":"connect.json","registrationTokenFile":"registration-token","credentialTtlSeconds":900}`, ConfigSchemaVersion, apiURL)
	if err := os.WriteFile(paths.connect, []byte(connect), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.enrollment, []byte(enrollment), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.token, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestEnrollmentUsesExactReleasedRequestAndActivatesOnlyAfterDurability(t *testing.T) {
	credential := credentialFor(33)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var seenIdempotency string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.EscapedPath() != "/v1/runners/"+testRunnerID+"/registration-redemptions" || request.Header.Get("Authorization") != "Bearer "+testToken || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request metadata = %s %s %#v", request.Method, request.URL.EscapedPath(), request.Header)
		}
		seenIdempotency = request.Header.Get("Idempotency-Key")
		var body redeemRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.CredentialTTLSeconds != 900 {
			t.Fatalf("request body = %#v, %v", body, err)
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(body.PossessionProof)
		if err != nil {
			t.Fatal(err)
		}
		tokenHash := sha256.Sum256([]byte(testToken))
		message := []byte("provenance.runner.registration.v1\norganization_id:" + testOrganizationID + "\nrunner_id:" + testRunnerID + "\nregistration_token_sha256:" + hex.EncodeToString(tokenHash[:]) + "\npublic_key_base64url:" + body.PublicKey + "\n")
		if !ed25519.Verify(publicKey, message, signature) {
			t.Fatal("possession proof did not verify")
		}
		fingerprint := sha256.Sum256(publicKey)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(redeemResponse{RunnerID: testRunnerID, OrganizationID: testOrganizationID, CredentialID: "60000000-0000-0000-0000-000000000011", Credential: credential, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:])})
	}))
	defer server.Close()
	server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	paths := setupEnrollment(t, server.URL, testToken)
	if err := Run(context.Background(), paths.enrollment, Options{HTTPClient: server.Client()}); err != nil {
		t.Fatal(err)
	}
	if len(seenIdempotency) < 8 {
		t.Fatalf("idempotency key = %q", seenIdempotency)
	}
	installed, err := os.ReadFile(paths.credential)
	if err != nil || string(installed) != credential {
		t.Fatalf("installed credential = %q, %v", installed, err)
	}
	if mode := fileMode(t, paths.credential); mode != 0o600 {
		t.Fatalf("credential mode = %o", mode)
	}
	if _, err := os.Stat(paths.token); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed token still exists: %v", err)
	}
	identityBytes, err := os.ReadFile(paths.identity)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(identityBytes, []byte(credential)) || bytes.Contains(identityBytes, []byte(testToken)) {
		t.Fatal("active identity retained a returned credential or registration token")
	}
	document, err := runneridentity.Decode(identityBytes)
	if err != nil || document.Phase != runneridentity.PhaseActive || !document.MatchesCredential(installed) {
		t.Fatalf("active identity = %#v, %v", document, err)
	}
	if _, err := gatewayclient.LoadConfig(paths.connect, "test"); err != nil {
		t.Fatalf("normal gateway startup rejected active enrollment: %v", err)
	}
	freshToken := tokenFor(92)
	if err := os.WriteFile(paths.token, []byte(freshToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), paths.enrollment, Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("active enrollment attempted another redemption")
		return nil, nil
	})}); err == nil || !strings.Contains(err.Error(), "left untouched") {
		t.Fatalf("active enrollment error = %v", err)
	}
	retained, err := os.ReadFile(paths.token)
	if err != nil || string(retained) != freshToken {
		t.Fatalf("active identity removed fresh token: %q, %v", retained, err)
	}
}

func TestResponseReceivedRecoveryInstallsWithoutHTTPAndRejectsMismatchedToken(t *testing.T) {
	for _, test := range []struct {
		name          string
		token         string
		wantSuccess   bool
		wantTokenFile bool
	}{
		{name: "matching token", token: testToken, wantSuccess: true},
		{name: "mismatched token", token: tokenFor(93), wantTokenFile: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := setupEnrollment(t, "https://api.example.test", test.token)
			tokenHash := sha256.Sum256([]byte(testToken))
			document, err := runneridentity.NewPrepared(testOrganizationID, testRunnerID, tokenHash, "response-recovery-test", 900, strings.NewReader(strings.Repeat("r", 32)))
			if err != nil {
				t.Fatal(err)
			}
			credential := credentialFor(94)
			credentialHash := sha256.Sum256([]byte(credential))
			now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			document, err = document.Received(runneridentity.Response{CredentialID: "60000000-0000-0000-0000-000000000094", Credential: credential, CredentialSHA256: hex.EncodeToString(credentialHash[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			opened, err := openStore(paths.identity, paths.credential, paths.token)
			if err != nil {
				t.Fatal(err)
			}
			if err := opened.WriteIdentity(document); err != nil {
				t.Fatal(err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			called := false
			err = Run(context.Background(), paths.enrollment, Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
				called = true
				return nil, errors.New("must not be called")
			})})
			if called {
				t.Fatal("response recovery called the registration authority")
			}
			if test.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := gatewayclient.LoadConfig(paths.connect, "test"); err != nil {
					t.Fatalf("recovered enrollment did not enable startup: %v", err)
				}
				identityData, _ := os.ReadFile(paths.identity)
				if bytes.Contains(identityData, []byte(credential)) {
					t.Fatal("recovered active identity retained credential plaintext")
				}
				if _, err := os.Stat(paths.token); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovered enrollment retained consumed token: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("mismatched recovery error = %v", err)
			}
			if _, err := os.Stat(paths.credential); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mismatched recovery installed credential: %v", err)
			}
			retained, readErr := os.ReadFile(paths.token)
			if readErr != nil || string(retained) != test.token {
				t.Fatalf("mismatched recovery changed token: %q, %v", retained, readErr)
			}
			identityData, readErr := os.ReadFile(paths.identity)
			identity, decodeErr := runneridentity.Decode(identityData)
			if readErr != nil || decodeErr != nil || identity.Phase != runneridentity.PhaseReceived {
				t.Fatalf("mismatched recovery changed identity: %#v read=%v decode=%v", identity, readErr, decodeErr)
			}
		})
	}
}

func TestLostSuccessRetryFailsClosedAndReplacementTokenSucceeds(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	var keys []string
	client := doerFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		if requests == 1 {
			return nil, errors.New("response lost after commit")
		}
		if requests == 2 {
			return problemResponse(http.StatusConflict, "credential_not_replayable"), nil
		}
		if request.Header.Get("Authorization") != "Bearer "+tokenFor(90) {
			return problemResponse(http.StatusUnauthorized, "registration_token_invalid"), nil
		}
		return successResponse(t, request, credentialFor(91)), nil
	})
	paths := setupEnrollment(t, "https://api.example.test", testToken)
	err := Run(context.Background(), paths.enrollment, Options{HTTPClient: client})
	assertEnrollmentError(t, err, "transport_ambiguous", true)
	if _, err := os.Stat(paths.credential); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ambiguous response activated credential: %v", err)
	}
	if _, err := gatewayclient.LoadConfig(paths.connect, "test"); err == nil {
		t.Fatal("gateway startup succeeded after ambiguous response")
	}
	err = Run(context.Background(), paths.enrollment, Options{HTTPClient: client})
	assertEnrollmentError(t, err, "credential_not_replayable", false)
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("retry idempotency keys = %#v", keys)
	}
	identityBytes, readErr := os.ReadFile(paths.identity)
	if readErr != nil {
		t.Fatal(readErr)
	}
	document, decodeErr := runneridentity.Decode(identityBytes)
	if decodeErr != nil || document.Phase != runneridentity.PhaseTerminal || document.PrivateKeySeed != "" || document.Terminal.Code != "credential_not_replayable" {
		t.Fatalf("terminal identity = %#v, %v", document, decodeErr)
	}
	if bytes.Contains(identityBytes, []byte(testToken)) || strings.Contains(err.Error(), testToken) {
		t.Fatal("terminal state or error disclosed a secret")
	}
	if _, statErr := os.Stat(paths.token); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("terminal token still exists: %v", statErr)
	}

	replacement := tokenFor(90)
	if writeErr := os.WriteFile(paths.token, []byte(replacement), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err := Run(context.Background(), paths.enrollment, Options{HTTPClient: client}); err != nil {
		t.Fatalf("replacement registration failed: %v", err)
	}
	if len(keys) != 3 || keys[2] == keys[1] {
		t.Fatalf("replacement attempt did not receive a new identity: %#v", keys)
	}
	if _, err := gatewayclient.LoadConfig(paths.connect, "test"); err != nil {
		t.Fatalf("replacement enrollment did not enable startup: %v", err)
	}
}

func TestEnrollmentConfigurationAndAuthorityResponsesFailClosed(t *testing.T) {
	t.Run("preexisting credential", func(t *testing.T) {
		paths := setupEnrollment(t, "https://api.example.test", testToken)
		oldCredential := []byte("legacy usable credential")
		if err := os.WriteFile(paths.credential, oldCredential, 0o600); err != nil {
			t.Fatal(err)
		}
		called := false
		err := Run(context.Background(), paths.enrollment, Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("must not be called")
		})})
		installed, readErr := os.ReadFile(paths.credential)
		if err == nil || called || readErr != nil || !bytes.Equal(installed, oldCredential) {
			t.Fatalf("preexisting credential result err=%v called=%t credential=%q read=%v", err, called, installed, readErr)
		}
	})

	t.Run("duplicate configuration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "enrollment.json")
		data := fmt.Sprintf(`{"schemaVersion":%q,"schemaVersion":%q}`, ConfigSchemaVersion, ConfigSchemaVersion)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("duplicate configuration member was accepted")
		}
	})
	t.Run("symbolic configuration", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(link); err == nil {
			t.Fatal("symbolic configuration was accepted")
		}
	})

	for name, response := range map[string]*http.Response{
		"wrong success media":   {StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader(`{}`))},
		"unknown success field": {StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"unknown":true}`))},
		"missing challenge":     {StatusCode: http.StatusUnauthorized, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: problemResponse(http.StatusUnauthorized, "registration_token_invalid").Body},
		"oversized":             {StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), maximumResponseBytes+1)))},
	} {
		t.Run(name, func(t *testing.T) {
			paths := setupEnrollment(t, "https://api.example.test", testToken)
			err := Run(context.Background(), paths.enrollment, Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) { return response, nil })})
			if err == nil || strings.Contains(err.Error(), testToken) {
				t.Fatalf("authority response error = %v", err)
			}
			if _, statErr := os.Stat(paths.credential); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid response installed credential: %v", statErr)
			}
			if _, statErr := os.Stat(paths.token); statErr != nil {
				t.Fatalf("non-terminal invalid response removed retry token: %v", statErr)
			}
		})
	}
}

func successResponse(t *testing.T, request *http.Request, credential string) *http.Response {
	t.Helper()
	var body redeemRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(publicKey)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	encoded, err := json.Marshal(redeemResponse{RunnerID: testRunnerID, OrganizationID: testOrganizationID, CredentialID: "60000000-0000-0000-0000-000000000012", Credential: credential, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:])})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}
}

func problemResponse(status int, code string) *http.Response {
	body := fmt.Sprintf(`{"type":"about:blank","title":"bounded failure","status":%d,"detail":"bounded","code":%q,"traceId":"test"}`, status, code)
	header := http.Header{"Content-Type": {"application/problem+json"}}
	if status == http.StatusUnauthorized {
		header.Set("WWW-Authenticate", `Bearer realm="runner-registration", error="invalid_token"`)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }

func credentialFor(fill byte) string {
	return "prc_v1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func tokenFor(fill byte) string {
	return "prr_v1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func assertEnrollmentError(t *testing.T, err error, code string, retryable bool) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != code || failure.Retryable != retryable {
		t.Fatalf("enrollment error = %#v, want %s retryable=%t", err, code, retryable)
	}
}
