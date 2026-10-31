package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	backupsDir       = "/backups"
	configDir        = "/config"
	stateFile        = configDir + "/state.json"
	sambaPrivateDir  = configDir + "/samba/private"
	sharesConf       = "/etc/samba/shares.conf"
	avahiServiceFile = "/etc/avahi/services/timemachine.service"
	forceUser        = "tmbackup" // owns all backup data on disk; created in the Dockerfile
	firstUID         = 20000      // UIDs for SMB login accounts start here
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "reset-admin":
		err = resetAdmin()
	default:
		err = fmt.Errorf("unknown command %q (want serve, healthcheck or reset-admin)", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func listenAddr() string {
	if a := os.Getenv("LISTEN_ADDR"); a != "" {
		return a
	}
	return ":8080"
}

func serve() error {
	if err := os.MkdirAll("/run/samba", 0o755); err != nil { //nolint:gosec // samba runtime dir must be world-readable
		return err
	}
	if err := os.MkdirAll(sambaPrivateDir, 0o700); err != nil {
		return err
	}
	store := &Store{path: stateFile}
	st, err := store.Get()
	if err != nil {
		return err
	}
	// /etc/passwd is not persisted, so recreate login accounts on every boot.
	if err := reconcileUsers(st); err != nil {
		return err
	}
	for _, r := range st.Repos {
		if err := ensureRepoDir(r.Name); err != nil {
			return err
		}
	}
	if err := writeConfigs(st); err != nil {
		return err
	}

	sup := newSupervisor()
	sup.start("smbd", "smbd", "--foreground", "--no-process-group", "--debug-stdout")
	sup.start("avahi", "avahi-daemon", "--no-rlimits")

	stats := newStatsCache()
	go stats.run(store)

	hostname, _ := os.Hostname()
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           newWeb(store, sup, stats, hostname).routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("web UI listening on %s", srv.Addr)
	err = srv.ListenAndServe()
	sup.stop()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func healthcheck() error {
	addr := listenAddr()
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}

func resetAdmin() error {
	store := &Store{path: stateFile}
	_, err := store.Update(func(st *State) error {
		st.Admin = nil
		return nil
	})
	if err == nil {
		fmt.Println("Admin account cleared. Open the web UI to set a new one.")
	}
	return err
}
