// Package secrets is a small in-process Go client for Secrets Manager.
//
// The client always sends bearer tokens in the Authorization header, requires
// HTTPS server URLs, and never logs token or secret material.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const maxResponseBody = 1 << 20

var (
	ErrInsecureURL        = errors.New("secrets: server URL must use https")
	ErrMissingServerURL   = errors.New("secrets: missing server URL")
	ErrMissingToken       = errors.New("secrets: missing token")
	ErrUnexpectedResponse = errors.New("secrets: unexpected response")
	ErrUnauthorized       = errors.New("secrets: unauthorized")
	ErrForbidden          = errors.New("secrets: forbidden")
	ErrNotFound           = errors.New("secrets: not found")
)

type StatusError struct {
	Code int
}

func (e StatusError) Error() string {
	return fmt.Sprintf("secrets: server returned HTTP %d", e.Code)
}

type Config struct {
	ServerURL  string
	Token      string
	HTTPClient *http.Client
}

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type Project struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// Secret stores a secret value in mutable memory so callers can zero it after
// use. Avoid converting it to string unless the receiving API requires one.
type Secret []byte

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, ErrMissingServerURL
	}
	if cfg.Token == "" {
		return nil, ErrMissingToken
	}

	parsed, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("secrets: invalid server URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, ErrInsecureURL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}

	return &Client{
		baseURL:    strings.TrimRight(cfg.ServerURL, "/"),
		token:      cfg.Token,
		httpClient: httpClient,
	}, nil
}

func (c *Client) GetSecrets(ctx context.Context, project string) (map[string]Secret, error) {
	var out map[string]Secret
	if err := c.doJSON(ctx, http.MethodGet, c.projectPath(project, "secrets"), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) SetSecret(ctx context.Context, project, key string, value Secret) error {
	body, err := json.Marshal(struct {
		Value Secret `json:"value"`
	}{Value: value})
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPut, c.projectPath(project, "secrets", key), body, nil)
}

func (c *Client) DeleteSecret(ctx context.Context, project, key string) error {
	return c.doJSON(ctx, http.MethodDelete, c.projectPath(project, "secrets", key), nil, nil)
}

func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/projects", nil, &out); err != nil {
		return nil, err
	}
	return out.Projects, nil
}

func (c *Client) projectPath(project string, parts ...string) string {
	path := "/v1/projects/" + url.PathEscape(project)
	for _, part := range parts {
		path += "/" + url.PathEscape(part)
	}
	return path
}

func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := statusError(resp.StatusCode); err != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		return err
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		return nil
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrUnexpectedResponse, err)
	}
	return nil
}

func statusError(code int) error {
	switch code {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	default:
		return StatusError{Code: code}
	}
}

func (s Secret) Bytes() []byte {
	out := make([]byte, len(s))
	copy(out, s)
	return out
}

func (s Secret) String() string {
	return "[secret]"
}

func (s *Secret) Zeroize() {
	if s == nil {
		return
	}
	for i := range *s {
		(*s)[i] = 0
	}
	*s = nil
}

func (s Secret) MarshalJSON() ([]byte, error) {
	if !utf8.Valid(s) {
		return nil, errors.New("secrets: secret value must be valid UTF-8")
	}
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for len(s) > 0 {
		r, size := utf8.DecodeRune(s)
		switch r {
		case '\\', '"':
			out = append(out, '\\', byte(r))
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				out = appendHexEscape(out, r)
			} else {
				out = append(out, s[:size]...)
			}
		}
		s = s[size:]
	}
	out = append(out, '"')
	return out, nil
}

func (s *Secret) UnmarshalJSON(data []byte) error {
	value, err := unquoteJSONBytes(data)
	if err != nil {
		return err
	}
	*s = Secret(value)
	return nil
}

func unquoteJSONBytes(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, errors.New("secrets: expected JSON string")
	}
	out := make([]byte, 0, len(data)-2)
	for i := 1; i < len(data)-1; i++ {
		c := data[i]
		if c == '\\' {
			if i+1 >= len(data)-1 {
				return nil, errors.New("secrets: invalid JSON string escape")
			}
			i++
			switch data[i] {
			case '"', '\\', '/':
				out = append(out, data[i])
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, next, err := parseJSONUnicodeEscape(data, i+1)
				if err != nil {
					return nil, err
				}
				out = utf8.AppendRune(out, r)
				i = next - 1
			default:
				return nil, errors.New("secrets: invalid JSON string escape")
			}
			continue
		}
		if c < 0x20 {
			return nil, errors.New("secrets: invalid JSON string control character")
		}
		out = append(out, c)
	}
	if !utf8.Valid(out) {
		return nil, errors.New("secrets: JSON string is not valid UTF-8")
	}
	return out, nil
}

func parseJSONUnicodeEscape(data []byte, start int) (rune, int, error) {
	r, next, err := parseHexRune(data, start)
	if err != nil {
		return 0, 0, err
	}
	if utf16.IsSurrogate(r) {
		if r < 0xD800 || r > 0xDBFF || next+6 > len(data) || data[next] != '\\' || data[next+1] != 'u' {
			return 0, 0, errors.New("secrets: invalid JSON unicode surrogate")
		}
		low, lowNext, err := parseHexRune(data, next+2)
		if err != nil {
			return 0, 0, err
		}
		decoded := utf16.DecodeRune(r, low)
		if decoded == unicodeReplacementRune {
			return 0, 0, errors.New("secrets: invalid JSON unicode surrogate")
		}
		return decoded, lowNext, nil
	}
	return r, next, nil
}

func parseHexRune(data []byte, start int) (rune, int, error) {
	if start+4 > len(data) {
		return 0, 0, errors.New("secrets: short JSON unicode escape")
	}
	var value rune
	for _, b := range data[start : start+4] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= rune(b - '0')
		case b >= 'a' && b <= 'f':
			value |= rune(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value |= rune(b-'A') + 10
		default:
			return 0, 0, errors.New("secrets: invalid JSON unicode escape")
		}
	}
	return value, start + 4, nil
}

func appendHexEscape(out []byte, r rune) []byte {
	const hex = "0123456789abcdef"
	return append(out, '\\', 'u', '0', '0', hex[(r>>4)&0xf], hex[r&0xf])
}

const unicodeReplacementRune = '\uFFFD'
