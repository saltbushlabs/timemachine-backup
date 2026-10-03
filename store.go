package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the whole persisted configuration. It is small, so it lives in a
// single JSON file that is re-read on every access; that keeps the file the
// only source of truth (the reset-admin command edits it from another process).
type State struct {
	Admin   *Admin  `json:"admin,omitempty"`
	NextUID int     `json:"next_uid"`
	Repos   []*Repo `json:"repos"`
}

type Admin struct {
	Username string `json:"username"`
	Salt     []byte `json:"salt"`
	Hash     []byte `json:"hash"`
}

type Repo struct {
	Name        string        `json:"name"`
	QuotaGB     int           `json:"quota_gb"` // 0 = unlimited
	Enabled     bool          `json:"enabled"`
	Created     time.Time     `json:"created"`
	Credentials []*Credential `json:"credentials"`
}

// Credential is an SMB login scoped to one repo. The password hash lives only
// in Samba's passdb; it is never stored here.
type Credential struct {
	Username string    `json:"username"`
	UID      int       `json:"uid"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created"`
}

func (st *State) Repo(name string) *Repo {
	for _, r := range st.Repos {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func (st *State) Credential(username string) (*Repo, *Credential) {
	for _, r := range st.Repos {
		for _, c := range r.Credentials {
			if c.Username == username {
				return r, c
			}
		}
	}
	return nil, nil
}

// Available reports whether the share should be served. A share with no
// enabled credentials must not be served: an empty "valid users" means anyone.
func (r *Repo) Available() bool {
	return r.Enabled && len(r.EnabledUsers()) > 0
}

func (r *Repo) EnabledUsers() []string {
	var users []string
	for _, c := range r.Credentials {
		if c.Enabled {
			users = append(users, c.Username)
		}
	}
	return users
}

type Store struct {
	mu   sync.Mutex
	path string
}

func (s *Store) Get() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Update runs fn on the current state and saves the result if fn succeeds.
// The lock is held throughout, so fn may perform side effects that must not
// interleave with other updates (creating system users, etc.).
func (s *Store) Update(fn func(*State) error) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return nil, err
	}
	if err := fn(st); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(s.path, b, 0o600); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) load() (*State, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{NextUID: firstUID}, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
