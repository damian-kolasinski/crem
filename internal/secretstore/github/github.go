// Package github stores secrets in GitHub Actions, for a repository or one of its environments.
package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// DefaultBaseURL is GitHub's REST API.
const DefaultBaseURL = "https://api.github.com"

// Store is one repository's Actions secrets, or one of its environment's.
type Store struct {
	baseURL     string
	repository  string
	environment string
	token       func() (string, error)
	http        *http.Client
	// key is the store's public key, fetched once.
	key *publicKey
}

type publicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

// New returns the secrets of repository ("owner/name"), or of its environment when one is given.
func New(baseURL, repository, environment string, token func() (string, error), client *http.Client) *Store {
	return &Store{baseURL: strings.TrimSuffix(baseURL, "/"), repository: repository, environment: environment, token: token, http: client}
}

func (s *Store) Describe() string {
	if s.environment != "" {
		return fmt.Sprintf("GitHub %s environment %s", s.repository, s.environment)
	}
	return "GitHub " + s.repository
}

func (s *Store) scope() string {
	if s.environment != "" {
		return "/repos/" + s.repository + "/environments/" + url.PathEscape(s.environment) + "/secrets"
	}
	return "/repos/" + s.repository + "/actions/secrets"
}

// Set encrypts the value with the repository's public key, as GitHub requires, and stores it.
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	if s.key == nil {
		var key publicKey
		if err := s.do(ctx, http.MethodGet, s.scope()+"/public-key", nil, &key); err != nil {
			return err
		}
		s.key = &key
	}
	key := *s.key
	publicKey, err := base64.StdEncoding.DecodeString(key.Key)
	if err != nil || len(publicKey) != 32 {
		return fmt.Errorf("%s returned an unreadable public key", s.Describe())
	}
	sealed, err := box.SealAnonymous(nil, value, (*[32]byte)(publicKey), rand.Reader)
	if err != nil {
		return err
	}
	return s.do(ctx, http.MethodPut, s.scope()+"/"+url.PathEscape(name), map[string]string{
		"encrypted_value": base64.StdEncoding.EncodeToString(sealed),
		"key_id":          key.KeyID,
	}, nil)
}

func (s *Store) Updated(ctx context.Context) (map[string]time.Time, error) {
	updated := map[string]time.Time{}
	for page := 1; ; page++ {
		var listing struct {
			TotalCount int `json:"total_count"`
			Secrets    []struct {
				Name      string    `json:"name"`
				UpdatedAt time.Time `json:"updated_at"`
			} `json:"secrets"`
		}
		if err := s.do(ctx, http.MethodGet, s.scope()+"?per_page=100&page="+strconv.Itoa(page), nil, &listing); err != nil {
			return nil, err
		}
		for _, secret := range listing.Secrets {
			updated[secret.Name] = secret.UpdatedAt
		}
		if len(listing.Secrets) == 0 || len(updated) >= listing.TotalCount {
			return updated, nil
		}
	}
}

func (s *Store) do(ctx context.Context, method, path string, body, result any) error {
	token, err := s.token()
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", s.Describe(), err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &failure)
		return fmt.Errorf("%s: %s %s failed (%d): %s", s.Describe(), method, strings.SplitN(path, "?", 2)[0], response.StatusCode, failure.Message)
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("%s returned unreadable JSON: %w", s.Describe(), err)
		}
	}
	return nil
}
