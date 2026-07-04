package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRejectsHTTP(t *testing.T) {
	_, err := New(Config{ServerURL: "http://example.test", Token: "tok"})
	if !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("expected ErrInsecureURL, got %v", err)
	}
}

func TestGetAndSetSecret(t *testing.T) {
	var sawGet bool
	var sawPut bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("authorization header mismatch: %q", got)
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/cdn/secrets":
			sawGet = true
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"DATABASE_URL":"postgres://secret"}`)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/projects/cdn/secrets/DATABASE_URL":
			sawPut = true
			var body struct {
				Value Secret `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode put body: %v", err)
			}
			if string(body.Value) != "postgres://new" {
				t.Fatalf("secret body mismatch: %q", string(body.Value))
			}
			fmt.Fprint(w, `{"key":"DATABASE_URL","version":2}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := New(Config{
		ServerURL:  server.URL,
		Token:      "tok",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	secrets, err := client.GetSecrets(context.Background(), "cdn")
	if err != nil {
		t.Fatalf("get secrets: %v", err)
	}
	if string(secrets["DATABASE_URL"]) != "postgres://secret" {
		t.Fatalf("secret mismatch: %q", string(secrets["DATABASE_URL"]))
	}

	if err := client.SetSecret(context.Background(), "cdn", "DATABASE_URL", Secret("postgres://new")); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if !sawGet || !sawPut {
		t.Fatalf("expected get and put requests, saw get=%v put=%v", sawGet, sawPut)
	}
}

func TestStatusErrorsAreTyped(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client, err := New(Config{
		ServerURL:  server.URL,
		Token:      "tok",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.GetSecrets(context.Background(), "cdn")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestSecretRedactsAndZeroizes(t *testing.T) {
	secret := Secret("value")
	if fmt.Sprint(secret) != "[secret]" {
		t.Fatalf("secret string form leaked: %s", secret)
	}
	copy := secret.Bytes()
	copy[0] = 'V'
	if fmt.Sprint(secret) != "[secret]" {
		t.Fatalf("secret String method should stay redacted")
	}
	if string([]byte(secret)) != "value" {
		t.Fatalf("Bytes returned shared storage")
	}
	secret.Zeroize()
	if secret != nil {
		t.Fatalf("secret was not cleared")
	}
}

func TestSecretJSONEscapes(t *testing.T) {
	input := Secret("line\nsnowman:\u2603")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}

	var output Secret
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal secret: %v", err)
	}
	if string([]byte(output)) != string([]byte(input)) {
		t.Fatalf("roundtrip mismatch: %q", string([]byte(output)))
	}
}
