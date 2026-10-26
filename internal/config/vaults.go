package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Vault is a configured vault: exactly one of Local and OnePassword is set.
type Vault struct {
	Local       *LocalVault
	OnePassword *OnePasswordVault
}

// LocalVault is a directory on this machine.
type LocalVault struct {
	// Path as written in the config; empty means ~/.crem/<team>.
	Path string
}

// OnePasswordVault is a vault in a 1Password account.
type OnePasswordVault struct {
	Vault   string
	Account string
}

// Directory resolves the vault's directory. It refuses directories inside the
// repository that holds the config, so identities are never committed.
func (v LocalVault) Directory(team string, environment Environment) (string, error) {
	directory := filepath.Join(environment.HomeDir, ".crem", team)
	if v.Path != "" {
		directory = expandPath(v.Path, environment.HomeDir, environment.ConfigDir)
	}
	directory, err := realPath(filepath.Clean(directory))
	if err != nil {
		return "", err
	}
	repository, err := repositoryRoot(environment.ConfigDir)
	if err != nil {
		return "", err
	}
	if repository != "" {
		inside, err := within(directory, repository)
		if err != nil {
			return "", err
		}
		if inside {
			return "", fmt.Errorf("local vault %s is inside the repository %s; keep identities outside it", directory, repository)
		}
	}
	return directory, nil
}

// within reports whether path is root or lies under it. It compares files rather than
// strings, so case-insensitive file systems cannot be fooled by a differently cased path.
func within(path, root string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil && os.SameFile(info, rootInfo) {
			return true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if filepath.Dir(current) == current {
			return false, nil
		}
	}
}

// repositoryRoot returns the nearest ancestor of directory that contains .git, or "" outside a repository.
func repositoryRoot(directory string) (string, error) {
	current, err := realPath(directory)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return current, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
}

// realPath resolves symlinks in the deepest existing ancestor, so a link cannot route a path into the repository.
func realPath(path string) (string, error) {
	var missing []string
	existing := path
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		missing = append([]string{filepath.Base(existing)}, missing...)
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{resolved}, missing...)...), nil
}
