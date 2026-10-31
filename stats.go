package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	statsInterval = 10 * time.Minute
	staleAfter    = 7 * 24 * time.Hour
)

type RepoStats struct {
	UsedBytes  int64
	LastBackup time.Time // zero if no backup bundle found
	Bundles    []string  // e.g. "Sams-MacBook.sparsebundle"
	Scanned    time.Time
}

// statsCache walks the repo directories in the background; disk usage of a
// multi-TB backup is too slow to compute on page load.
type statsCache struct {
	mu      sync.RWMutex
	m       map[string]RepoStats
	trigger chan struct{}
}

func newStatsCache() *statsCache {
	return &statsCache{m: map[string]RepoStats{}, trigger: make(chan struct{}, 1)}
}

func (c *statsCache) get(name string) RepoStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[name]
}

func (c *statsCache) refresh() {
	select {
	case c.trigger <- struct{}{}:
	default:
	}
}

func (c *statsCache) run(store *Store) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		st, err := store.Get()
		if err != nil {
			log.Printf("stats: %v", err)
		} else {
			m := map[string]RepoStats{}
			for _, r := range st.Repos {
				m[r.Name] = scanRepo(repoPath(r.Name))
			}
			c.mu.Lock()
			c.m = m
			c.mu.Unlock()
		}
		select {
		case <-t.C:
		case <-c.trigger:
		}
	}
}

func scanRepo(dir string) RepoStats {
	s := RepoStats{Scanned: time.Now()}
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				s.UsedBytes += st.Blocks * 512 // allocated size; bundles are sparse
			}
		}
		return nil
	})

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".sparsebundle") && !strings.HasSuffix(e.Name(), ".backupbundle") {
			continue
		}
		s.Bundles = append(s.Bundles, e.Name())
		// Time Machine rewrites the plists in the bundle root at the end of
		// every backup; band files deeper down don't bump directory mtimes.
		files, _ := os.ReadDir(filepath.Join(dir, e.Name()))
		for _, f := range files {
			if info, err := f.Info(); err == nil && info.ModTime().After(s.LastBackup) {
				s.LastBackup = info.ModTime()
			}
		}
	}
	return s
}
