// Package vaultsync copies signing identities between vaults, so every configured
// vault holds every identity any of them holds.
package vaultsync

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/vault"
)

// Copy is an identity to copy into vaults that lack it.
type Copy struct {
	CertificateID string
	// From are the vaults holding it, tried in order until one holds a usable copy.
	From []vault.Vault
	To   []vault.Vault
}

// Plan lists the copies that make every vault hold every identity.
type Plan struct {
	Copies []Copy
	// InSync counts identities every vault already holds.
	InSync int
}

// Prepare reads every vault. A vault not set up on this machine counts as empty, since saving creates it.
func Prepare(ctx context.Context, vaults []vault.Vault, team string) (Plan, error) {
	if len(vaults) < 2 {
		return Plan{}, errors.New("crem.yaml lists fewer than two vaults; add the vault to copy identities into")
	}
	// Holders are tracked by position in vaults, so adapters need not be comparable.
	holders := map[string][]int{}
	var ids []string
	for index, store := range vaults {
		held, err := store.List(ctx, team)
		if err != nil && !errors.Is(err, vault.ErrNotSetUp) {
			return Plan{}, fmt.Errorf("%s: %w", store.Describe(), err)
		}
		for _, id := range held {
			if _, seen := holders[id]; !seen {
				ids = append(ids, id)
			}
			holders[id] = append(holders[id], index)
		}
	}
	slices.Sort(ids)
	var plan Plan
	for _, id := range ids {
		item := Copy{CertificateID: id}
		for index, store := range vaults {
			if slices.Contains(holders[id], index) {
				item.From = append(item.From, store)
			} else {
				item.To = append(item.To, store)
			}
		}
		if len(item.To) == 0 {
			plan.InSync++
			continue
		}
		plan.Copies = append(plan.Copies, item)
	}
	return plan, nil
}

// Result says what happened to an identity in one vault.
type Result struct {
	CertificateID string
	To            string
	// AlreadyHeld is true when the vault held an identity for the certificate by the time it was saved.
	AlreadyHeld bool
}

// Execute copies each identity from the first vault holding a copy whose .p12 opens with its
// password, and stops at the first failure.
func Execute(ctx context.Context, plan Plan, team string) ([]Result, error) {
	var results []Result
	for _, item := range plan.Copies {
		entry, err := usableEntry(ctx, item, team)
		if err != nil {
			return results, err
		}
		for _, store := range item.To {
			err := store.Save(ctx, entry)
			if err != nil && !errors.Is(err, vault.ErrExists) {
				return results, fmt.Errorf("saving %s to %s: %w", item.CertificateID, store.Describe(), err)
			}
			results = append(results, Result{CertificateID: item.CertificateID, To: store.Describe(), AlreadyHeld: err != nil})
		}
	}
	return results, nil
}

func usableEntry(ctx context.Context, item Copy, team string) (vault.Entry, error) {
	var failures []error
	for _, source := range item.From {
		entry, err := source.Load(ctx, team, item.CertificateID)
		if err == nil {
			if _, err = identity.Open(entry.P12, entry.Password); err == nil {
				return entry, nil
			}
		}
		failures = append(failures, fmt.Errorf("%s: %w", source.Describe(), err))
	}
	return vault.Entry{}, fmt.Errorf("no vault holds a usable identity for %s: %w", item.CertificateID, errors.Join(failures...))
}
