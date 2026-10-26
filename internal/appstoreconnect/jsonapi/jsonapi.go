// Package jsonapi sends authenticated JSON:API requests to App Store Connect,
// following pagination and turning error documents into errors.
package jsonapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is App Store Connect's API endpoint.
const DefaultBaseURL = "https://api.appstoreconnect.apple.com"

// TokenSource provides bearer tokens.
type TokenSource interface {
	Token() (string, error)
}

// Client sends requests to one API endpoint.
type Client struct {
	base   *url.URL
	http   *http.Client
	tokens TokenSource
	// sleep waits before a retry; replaced in tests.
	sleep func(context.Context, time.Duration) error
}

// New returns a client for the API at baseURL.
func New(baseURL string, tokens TokenSource, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{base: base, http: httpClient, tokens: tokens, sleep: sleepContext}, nil
}

// Resource is a JSON:API resource object.
type Resource struct {
	Type          string                  `json:"type"`
	ID            string                  `json:"id"`
	Attributes    json.RawMessage         `json:"attributes,omitempty"`
	Relationships map[string]Relationship `json:"relationships,omitempty"`
}

// Relationship is a resource's link to one or many others.
type Relationship struct {
	Data json.RawMessage `json:"data,omitempty"`
}

type identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// IDs returns the IDs of the related resources.
func (r Relationship) IDs() []string {
	trimmed := bytes.TrimSpace(r.Data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if trimmed[0] == '[' {
		var many []identifier
		if json.Unmarshal(trimmed, &many) != nil {
			return nil
		}
		ids := make([]string, len(many))
		for index, related := range many {
			ids[index] = related.ID
		}
		return ids
	}
	var one identifier
	if json.Unmarshal(trimmed, &one) != nil || one.ID == "" {
		return nil
	}
	return []string{one.ID}
}

// Document is a JSON:API response document.
type Document struct {
	Data     json.RawMessage `json:"data"`
	Included []Resource      `json:"included"`
	Links    struct {
		Next string `json:"next"`
	} `json:"links"`
	Meta struct {
		Paging struct {
			Total int `json:"total"`
		} `json:"paging"`
	} `json:"meta"`
}

// Error is an API request that failed.
type Error struct {
	Method string
	Path   string
	Status int
	Code   string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("App Store Connect %s %s failed (%d %s): %s", e.Method, e.Path, e.Status, e.Code, e.Detail)
}

// GetAll fetches every page of a collection.
func (c *Client) GetAll(ctx context.Context, path string, query url.Values) (data, included []Resource, err error) {
	next := c.resolve(path, query)
	visited := map[string]bool{}
	for next != nil {
		if visited[next.String()] {
			return nil, nil, fmt.Errorf("App Store Connect repeated pagination link %s", next)
		}
		visited[next.String()] = true
		document, err := c.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, nil, err
		}
		var page []Resource
		if err := json.Unmarshal(document.Data, &page); err != nil {
			return nil, nil, fmt.Errorf("App Store Connect %s returned an invalid collection: %w", next.Path, err)
		}
		data = append(data, page...)
		included = append(included, document.Included...)
		next = nil
		if document.Links.Next != "" {
			link, err := url.Parse(document.Links.Next)
			if err != nil || link.Scheme != c.base.Scheme || link.Host != c.base.Host {
				return nil, nil, fmt.Errorf("App Store Connect returned an unexpected pagination link %q", document.Links.Next)
			}
			next = link
		}
	}
	return data, included, nil
}

func (c *Client) resolve(path string, query url.Values) *url.URL {
	resolved := *c.base
	resolved.Path = strings.TrimSuffix(c.base.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	resolved.RawQuery = query.Encode()
	return &resolved
}

const (
	maxAttempts      = 4
	maxRetryDelay    = time.Minute
	maxResponseBytes = 64 << 20
)

func (c *Client) do(ctx context.Context, method string, target *url.URL, body any) (Document, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return Document{}, err
		}
	}
	for attempt := 1; ; attempt++ {
		document, retryAfter, err := c.attempt(ctx, method, target, payload)
		// Only reads are retried: a failed write may still have been applied.
		if retryAfter < 0 || method != http.MethodGet || attempt == maxAttempts {
			return document, err
		}
		if err := c.sleep(ctx, retryAfter); err != nil {
			return Document{}, err
		}
	}
}

// attempt sends one request. A non-negative retryAfter means the request may be retried after that delay.
func (c *Client) attempt(ctx context.Context, method string, target *url.URL, payload []byte) (Document, time.Duration, error) {
	token, err := c.tokens.Token()
	if err != nil {
		return Document{}, -1, err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return Document{}, -1, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return Document{}, -1, fmt.Errorf("App Store Connect %s %s: %w", method, target.Path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return Document{}, -1, err
	}
	if len(data) > maxResponseBytes {
		return Document{}, -1, fmt.Errorf("App Store Connect %s %s returned more than %d MB", method, target.Path, maxResponseBytes>>20)
	}

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		var document Document
		if len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &document); err != nil {
				return Document{}, -1, fmt.Errorf("App Store Connect %s %s returned invalid JSON: %w", method, target.Path, err)
			}
		}
		return document, -1, nil
	}

	apiError := &Error{Method: method, Path: target.Path, Status: response.StatusCode, Code: "UNKNOWN", Detail: http.StatusText(response.StatusCode)}
	var failure struct {
		Errors []struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &failure) == nil && len(failure.Errors) > 0 {
		first := failure.Errors[0]
		apiError.Code = first.Code
		apiError.Detail = strings.TrimSpace(first.Detail)
		if apiError.Detail == "" {
			apiError.Detail = first.Title
		}
	}
	retryAfter := time.Duration(-1)
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		retryAfter = time.Second
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds >= 0 {
			retryAfter = min(time.Duration(seconds)*time.Second, maxRetryDelay)
		}
	}
	return Document{}, retryAfter, apiError
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
