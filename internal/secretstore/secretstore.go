// Package secretstore defines where CI reads its signing secrets from.
package secretstore

import (
	"context"
	"time"
)

// Store is a CI system's secret store.
type Store interface {
	// Describe names the store for people.
	Describe() string
	// Set creates or replaces a secret.
	Set(ctx context.Context, name string, value []byte) error
	// Updated returns when each existing secret was last updated, by name.
	Updated(ctx context.Context) (map[string]time.Time, error)
}
