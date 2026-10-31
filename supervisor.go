package main

import (
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// supervisor keeps smbd and avahi-daemon running as children of this process
// and restarts them with backoff if they exit.
type supervisor struct {
	mu       sync.Mutex
	procs    map[string]*exec.Cmd // name -> running command, nil while down
	stopping bool
	wg       sync.WaitGroup
}

func newSupervisor() *supervisor {
	return &supervisor{procs: map[string]*exec.Cmd{}}
}

func (s *supervisor) start(name string, argv ...string) {
	s.mu.Lock()
	s.procs[name] = nil
	s.mu.Unlock()
	s.wg.Add(1)
	go s.loop(name, argv)
}

func (s *supervisor) loop(name string, argv []string) {
	defer s.wg.Done()
	backoff := time.Second
	for {
		cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // argv is fixed by the program, not user input
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		started := time.Now()

		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return
		}
		err := cmd.Start()
		if err == nil {
			s.procs[name] = cmd
		}
		s.mu.Unlock()

		if err == nil {
			err = cmd.Wait()
			s.mu.Lock()
			s.procs[name] = nil
			stopping := s.stopping
			s.mu.Unlock()
			if stopping {
				return
			}
		}
		log.Printf("%s exited: %v; restarting in %s", name, err, backoff)
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, 30*time.Second)
	}
}

// reload asks every child to re-read its configuration.
func (s *supervisor) reload() {
	s.signal(syscall.SIGHUP)
}

func (s *supervisor) signal(sig os.Signal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cmd := range s.procs {
		if cmd != nil {
			_ = cmd.Process.Signal(sig) // process may already have exited
		}
	}
}

func (s *supervisor) healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cmd := range s.procs {
		if cmd == nil {
			return false
		}
	}
	return true
}

func (s *supervisor) stop() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.signal(syscall.SIGTERM)

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.signal(syscall.SIGKILL)
	}
}
