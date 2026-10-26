// Package onepassword keeps signing identities in a 1Password vault through the op CLI.
package onepassword

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/damian-kolasinski/crem/internal/vault"
)

// Runner runs op with arguments and stdin. Secrets only ever travel on stdin.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

// CLI runs the op executable.
type CLI struct{}

func (CLI) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "op", args...)
	// Read commands get no stdin: op treats piped lines as item specifiers.
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("the 1Password CLI (op) is not installed; see https://developer.1password.com/docs/cli/get-started/")
		}
		return nil, fmt.Errorf("op %s: %v: %s", args[0]+" "+args[1], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Vault is one 1Password vault.
type Vault struct {
	name    string
	account string
	op      Runner
}

// New returns the 1Password vault with the name, in the account when one is given.
func New(name, account string, op Runner) *Vault {
	return &Vault{name: name, account: account, op: op}
}

func (v *Vault) Describe() string {
	if v.account != "" {
		return fmt.Sprintf("1Password %s (%s)", v.name, v.account)
	}
	return "1Password " + v.name
}

// Items are tagged crem/<team>/<certificate ID>, so listing needs no secret reads.
func teamTag(team string) string { return "crem/" + team }

func certificateTag(team, certificateID string) string { return teamTag(team) + "/" + certificateID }

const (
	fieldPassword      = "password"
	fieldP12           = "p12"
	fieldCertificateID = "certificateId"
	fieldSerialNumber  = "serialNumber"
	fieldExpiresAt     = "expiresAt"
	fieldTeam          = "team"
)

var fieldIDsByLabel = map[string]string{
	"p12 password":   fieldPassword,
	"p12 (base64)":   fieldP12,
	"certificate ID": fieldCertificateID,
	"serial number":  fieldSerialNumber,
	"expires":        fieldExpiresAt,
	"team":           fieldTeam,
}

type item struct {
	ID       string   `json:"id,omitempty"`
	Title    string   `json:"title,omitempty"`
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Fields   []field  `json:"fields,omitempty"`
}

type field struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

func (v *Vault) args(args ...string) []string {
	args = append(args, "--vault", v.name, "--format", "json")
	if v.account != "" {
		args = append(args, "--account", v.account)
	}
	return args
}

func (v *Vault) Save(ctx context.Context, entry vault.Entry) error {
	existing, err := v.find(ctx, certificateTag(entry.Team, entry.CertificateID))
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return fmt.Errorf("%s in %s: %w", entry.CertificateID, v.Describe(), vault.ErrExists)
	}
	created := item{
		Title:    fmt.Sprintf("Apple Distribution %s (%s)", entry.SerialNumber, entry.Team),
		Category: "PASSWORD",
		Tags:     []string{"crem", teamTag(entry.Team), certificateTag(entry.Team, entry.CertificateID)},
		Fields: []field{
			{ID: fieldPassword, Type: "CONCEALED", Purpose: "PASSWORD", Label: "p12 password", Value: entry.Password},
			{ID: fieldP12, Type: "CONCEALED", Label: "p12 (base64)", Value: base64.StdEncoding.EncodeToString(entry.P12)},
			{ID: fieldCertificateID, Type: "STRING", Label: "certificate ID", Value: entry.CertificateID},
			{ID: fieldSerialNumber, Type: "STRING", Label: "serial number", Value: entry.SerialNumber},
			{ID: fieldExpiresAt, Type: "STRING", Label: "expires", Value: entry.ExpiresAt.UTC().Format(time.RFC3339)},
			{ID: fieldTeam, Type: "STRING", Label: "team", Value: entry.Team},
			{ID: "notesPlain", Type: "STRING", Purpose: "NOTES", Label: "notesPlain", Value: "Signing identity created by crem. The p12 field is the base64 of the .p12 file."},
		},
	}
	template, err := json.Marshal(created)
	if err != nil {
		return err
	}
	// Tags go on the command line too: the template's tags key is undocumented.
	_, err = v.op.Run(ctx, template, v.args("item", "create", "--tags", strings.Join(created.Tags, ","), "-")...)
	return err
}

func (v *Vault) Load(ctx context.Context, team, certificateID string) (vault.Entry, error) {
	found, err := v.find(ctx, certificateTag(team, certificateID))
	if err != nil {
		return vault.Entry{}, err
	}
	if len(found) == 0 {
		return vault.Entry{}, fmt.Errorf("%s in %s: %w", certificateID, v.Describe(), vault.ErrNotFound)
	}
	if len(found) > 1 {
		return vault.Entry{}, fmt.Errorf("%s holds %d items tagged %s; keep one", v.Describe(), len(found), certificateTag(team, certificateID))
	}
	output, err := v.op.Run(ctx, nil, v.args("item", "get", found[0].ID, "--reveal")...)
	if err != nil {
		return vault.Entry{}, err
	}
	var stored item
	if err := json.Unmarshal(output, &stored); err != nil {
		return vault.Entry{}, fmt.Errorf("op item get returned unreadable JSON: %w", err)
	}
	// Fields are found by ID or label: op may assign its own IDs to custom fields.
	values := map[string]string{}
	for _, field := range stored.Fields {
		values[field.ID] = field.Value
	}
	for _, field := range stored.Fields {
		if id, ok := fieldIDsByLabel[field.Label]; ok && values[id] == "" {
			values[id] = field.Value
		}
	}
	p12, err := base64.StdEncoding.DecodeString(values[fieldP12])
	if err != nil || len(p12) == 0 || values[fieldPassword] == "" {
		return vault.Entry{}, fmt.Errorf("%s item %s lacks a readable p12 and password", v.Describe(), stored.ID)
	}
	expiresAt, err := time.Parse(time.RFC3339, values[fieldExpiresAt])
	if err != nil {
		return vault.Entry{}, fmt.Errorf("%s item %s has an unreadable expiry: %w", v.Describe(), stored.ID, err)
	}
	return vault.Entry{
		Team:          team,
		CertificateID: certificateID,
		SerialNumber:  values[fieldSerialNumber],
		ExpiresAt:     expiresAt,
		P12:           p12,
		Password:      values[fieldPassword],
	}, nil
}

func (v *Vault) List(ctx context.Context, team string) ([]string, error) {
	found, err := v.find(ctx, teamTag(team))
	if err != nil {
		return nil, err
	}
	prefix := teamTag(team) + "/"
	var ids []string
	for _, item := range found {
		for _, tag := range item.Tags {
			if id, ok := strings.CutPrefix(tag, prefix); ok && id != "" && !strings.Contains(id, "/") && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// find lists items carrying the tag. op also matches nested tags, so results are filtered to exact matches.
func (v *Vault) find(ctx context.Context, tag string) ([]item, error) {
	output, err := v.op.Run(ctx, nil, v.args("item", "list", "--tags", tag)...)
	if err != nil {
		return nil, err
	}
	var items []item
	if err := json.Unmarshal(output, &items); err != nil {
		return nil, fmt.Errorf("op item list returned unreadable JSON: %w", err)
	}
	return slices.DeleteFunc(items, func(candidate item) bool { return !slices.Contains(candidate.Tags, tag) }), nil
}
