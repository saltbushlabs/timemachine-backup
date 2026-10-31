package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	sessionCookie = "tm_session"
	sessionTTL    = 12 * time.Hour
	pbkdf2Iter    = 600_000
)

type web struct {
	store    *Store
	sup      *supervisor
	stats    *statsCache
	hostname string
	pages    map[string]*template.Template

	mu       sync.Mutex
	sessions map[string]time.Time
}

type repoView struct {
	*Repo
	Stats RepoStats
	Stale bool
}

type secret struct {
	Username, Password, TmutilURL string
}

type pageData struct {
	Title      string
	Error      string
	Authed     bool
	Hostname   string
	Repos      []repoView
	Repo       *repoView
	Secret     *secret
	FreeBytes  int64
	TotalBytes int64
}

func newWeb(store *Store, sup *supervisor, stats *statsCache, hostname string) *web {
	funcs := template.FuncMap{
		"bytes": formatBytes,
		"ago":   formatAgo,
		"shq":   func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" },
	}
	pages := map[string]*template.Template{}
	for _, p := range []string{"login", "setup", "repos", "repo", "credential"} {
		pages[p] = template.Must(template.New("layout.html").Funcs(funcs).
			ParseFS(templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
	return &web{store: store, sup: sup, stats: stats, hostname: hostname, pages: pages, sessions: map[string]time.Time{}}
}

func (w *web) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", w.healthz)
	mux.HandleFunc("GET /setup", w.setupPage)
	mux.HandleFunc("POST /setup", w.setup)
	mux.HandleFunc("GET /login", w.loginPage)
	mux.HandleFunc("POST /login", w.login)

	auth := http.NewServeMux()
	auth.HandleFunc("POST /logout", w.logout)
	auth.HandleFunc("GET /{$}", w.reposPage)
	auth.HandleFunc("POST /repos", w.createRepo)
	auth.HandleFunc("GET /repos/{name}", w.repoPage)
	auth.HandleFunc("POST /repos/{name}/settings", w.updateRepo)
	auth.HandleFunc("POST /repos/{name}/delete", w.deleteRepo)
	auth.HandleFunc("POST /repos/{name}/credentials", w.createCredential)
	auth.HandleFunc("POST /repos/{name}/credentials/{user}/reset", w.resetCredential)
	auth.HandleFunc("POST /repos/{name}/credentials/{user}/toggle", w.toggleCredential)
	auth.HandleFunc("POST /repos/{name}/credentials/{user}/delete", w.deleteCredential)
	mux.Handle("/", w.requireAuth(auth))
	return mux
}

func (w *web) render(rw http.ResponseWriter, page string, status int, d pageData) {
	d.Hostname = w.hostname
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	if err := w.pages[page].Execute(rw, d); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func (w *web) fail(rw http.ResponseWriter, err error) {
	log.Printf("error: %v", err)
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}

// apply pushes the saved state to Samba and Avahi.
func (w *web) apply(st *State) error {
	if err := writeConfigs(st); err != nil {
		return err
	}
	w.sup.reload()
	return nil
}

// ---- health ----

func (w *web) healthz(rw http.ResponseWriter, r *http.Request) {
	if !w.sup.healthy() {
		http.Error(rw, "service down", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(rw, "ok")
}

// ---- admin auth ----

func hashPassword(pw string, salt []byte) []byte {
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		panic(err) // only fails for invalid parameters
	}
	return h
}

func (w *web) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		st, err := w.store.Get()
		if err != nil {
			w.fail(rw, err)
			return
		}
		if st.Admin == nil {
			http.Redirect(rw, r, "/setup", http.StatusSeeOther)
			return
		}
		if !w.validSession(r) {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *web) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	exp, ok := w.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(w.sessions, c.Value)
		return false
	}
	return true
}

func (w *web) startSession(rw http.ResponseWriter, r *http.Request) {
	token := rand.Text()
	w.mu.Lock()
	now := time.Now()
	for t, exp := range w.sessions {
		if now.After(exp) {
			delete(w.sessions, t)
		}
	}
	w.sessions[token] = now.Add(sessionTTL)
	w.mu.Unlock()
	setSessionCookie(rw, r, token, int(sessionTTL.Seconds()))
}

// setSessionCookie sets or (with maxAge < 0) clears the session cookie.
// SameSite=Strict keeps other sites from submitting our forms with it. Secure
// is set only when the request arrived over HTTPS, because the UI is usually
// served over plain HTTP on the LAN and a Secure cookie would never be sent.
func setSessionCookie(rw http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(rw, &http.Cookie{ //nolint:gosec // Secure depends on the request scheme, see above
		Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (w *web) setupPage(rw http.ResponseWriter, r *http.Request) {
	st, err := w.store.Get()
	if err != nil {
		w.fail(rw, err)
		return
	}
	if st.Admin != nil {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	w.render(rw, "setup", http.StatusOK, pageData{Title: "Set up admin"})
}

func (w *web) setup(rw http.ResponseWriter, r *http.Request) {
	username, pw := r.FormValue("username"), r.FormValue("password")
	_, err := w.store.Update(func(st *State) error {
		if st.Admin != nil {
			return errors.New("admin already configured")
		}
		if username == "" {
			return errors.New("username is required")
		}
		if err := validatePassword(pw); err != nil {
			return err
		}
		if pw != r.FormValue("confirm") {
			return errors.New("passwords do not match")
		}
		salt := make([]byte, 16)
		_, _ = rand.Read(salt) // crypto/rand.Read never fails
		st.Admin = &Admin{Username: username, Salt: salt, Hash: hashPassword(pw, salt)}
		return nil
	})
	if err != nil {
		w.render(rw, "setup", http.StatusBadRequest, pageData{Title: "Set up admin", Error: err.Error()})
		return
	}
	w.startSession(rw, r)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *web) loginPage(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, "login", http.StatusOK, pageData{Title: "Log in"})
}

func (w *web) login(rw http.ResponseWriter, r *http.Request) {
	st, err := w.store.Get()
	if err != nil {
		w.fail(rw, err)
		return
	}
	if st.Admin == nil {
		http.Redirect(rw, r, "/setup", http.StatusSeeOther)
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(r.FormValue("username")), []byte(st.Admin.Username)) == 1
	pwOK := subtle.ConstantTimeCompare(hashPassword(r.FormValue("password"), st.Admin.Salt), st.Admin.Hash) == 1
	if !userOK || !pwOK {
		time.Sleep(time.Second) // slow down guessing
		w.render(rw, "login", http.StatusUnauthorized, pageData{Title: "Log in", Error: "Invalid username or password"})
		return
	}
	w.startSession(rw, r)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *web) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		w.mu.Lock()
		delete(w.sessions, c.Value)
		w.mu.Unlock()
	}
	setSessionCookie(rw, r, "", -1)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

// ---- repositories ----

func (w *web) view(r *Repo) repoView {
	s := w.stats.get(r.Name)
	stale := r.Available() && (s.LastBackup.IsZero() && time.Since(r.Created) > staleAfter ||
		!s.LastBackup.IsZero() && time.Since(s.LastBackup) > staleAfter)
	return repoView{Repo: r, Stats: s, Stale: stale}
}

func (w *web) reposPage(rw http.ResponseWriter, r *http.Request) {
	w.renderRepos(rw, http.StatusOK, "")
}

func (w *web) renderRepos(rw http.ResponseWriter, status int, errMsg string) {
	st, err := w.store.Get()
	if err != nil {
		w.fail(rw, err)
		return
	}
	d := pageData{Title: "Repositories", Authed: true, Error: errMsg}
	for _, repo := range st.Repos {
		d.Repos = append(d.Repos, w.view(repo))
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(backupsDir, &fs) == nil {
		d.FreeBytes = int64(fs.Bavail) * fs.Bsize  //nolint:gosec // block counts fit in int64
		d.TotalBytes = int64(fs.Blocks) * fs.Bsize //nolint:gosec // block counts fit in int64
	}
	w.render(rw, "repos", status, d)
}

func parseQuota(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	q, err := strconv.Atoi(s)
	if err != nil || q < 0 {
		return 0, errors.New("quota must be a whole number of GB (0 = unlimited)")
	}
	return q, nil
}

func (w *web) createRepo(rw http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	st, err := w.store.Update(func(st *State) error {
		if err := validateRepoName(name); err != nil {
			return err
		}
		if st.Repo(name) != nil {
			return fmt.Errorf("repository %q already exists", name)
		}
		quota, err := parseQuota(r.FormValue("quota_gb"))
		if err != nil {
			return err
		}
		// An existing directory (from a repo deleted with "keep data") is reused.
		if err := ensureRepoDir(name); err != nil {
			return err
		}
		st.Repos = append(st.Repos, &Repo{Name: name, QuotaGB: quota, Enabled: true, Created: time.Now()})
		return nil
	})
	if err != nil {
		w.renderRepos(rw, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.apply(st); err != nil {
		w.fail(rw, err)
		return
	}
	w.stats.refresh()
	http.Redirect(rw, r, "/repos/"+name, http.StatusSeeOther) //nolint:gosec // same-origin path to an existing repo
}

func (w *web) repoPage(rw http.ResponseWriter, r *http.Request) {
	w.renderRepo(rw, r, http.StatusOK, "", nil)
}

func (w *web) renderRepo(rw http.ResponseWriter, r *http.Request, status int, errMsg string, sec *secret) {
	st, err := w.store.Get()
	if err != nil {
		w.fail(rw, err)
		return
	}
	repo := st.Repo(r.PathValue("name"))
	if repo == nil {
		http.NotFound(rw, r)
		return
	}
	v := w.view(repo)
	page := "repo"
	if sec != nil {
		page = "credential"
	}
	w.render(rw, page, status, pageData{Title: repo.Name, Authed: true, Repo: &v, Error: errMsg, Secret: sec})
}

// updateRepoWith mutates the repo named in the URL, saves, and applies the
// config. It writes the error response itself and reports whether to continue.
func (w *web) updateRepoWith(rw http.ResponseWriter, r *http.Request, fn func(st *State, repo *Repo) error) bool {
	st, err := w.store.Update(func(st *State) error {
		repo := st.Repo(r.PathValue("name"))
		if repo == nil {
			return errNotFound
		}
		return fn(st, repo)
	})
	if errors.Is(err, errNotFound) {
		http.NotFound(rw, r)
		return false
	}
	if err != nil {
		w.renderRepo(rw, r, http.StatusBadRequest, err.Error(), nil)
		return false
	}
	if err := w.apply(st); err != nil {
		w.fail(rw, err)
		return false
	}
	return true
}

var errNotFound = errors.New("not found")

func (w *web) updateRepo(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	disabled := false
	ok := w.updateRepoWith(rw, r, func(_ *State, repo *Repo) error {
		quota, err := parseQuota(r.FormValue("quota_gb"))
		if err != nil {
			return err
		}
		repo.QuotaGB = quota
		enabled := r.FormValue("enabled") == "on"
		disabled = repo.Enabled && !enabled
		repo.Enabled = enabled
		return nil
	})
	if !ok {
		return
	}
	if disabled {
		closeShare(name)
	}
	http.Redirect(rw, r, "/repos/"+name, http.StatusSeeOther) //nolint:gosec // same-origin path to an existing repo
}

func (w *web) deleteRepo(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	wipe := r.FormValue("wipe") == "on"
	st, err := w.store.Update(func(st *State) error {
		repo := st.Repo(name)
		if repo == nil {
			return errNotFound
		}
		if r.FormValue("confirm") != name {
			return errors.New("type the repository name to confirm deletion")
		}
		for _, c := range repo.Credentials {
			if err := deleteUser(c.Username); err != nil {
				log.Printf("delete user %s: %v", c.Username, err)
			}
		}
		for i, rr := range st.Repos {
			if rr == repo {
				st.Repos = append(st.Repos[:i], st.Repos[i+1:]...)
				break
			}
		}
		return nil
	})
	if errors.Is(err, errNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.renderRepo(rw, r, http.StatusBadRequest, err.Error(), nil)
		return
	}
	closeShare(name)
	if err := w.apply(st); err != nil {
		w.fail(rw, err)
		return
	}
	if wipe {
		// name was validated when the repo was created, so this stays inside backupsDir.
		if err := os.RemoveAll(repoPath(name)); err != nil {
			w.fail(rw, err)
			return
		}
	}
	w.stats.refresh()
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

// ---- credentials ----

func newSecret(host, repo, username, password string) *secret {
	u := url.URL{Scheme: "smb", User: url.UserPassword(username, password), Host: host + ".local", Path: "/" + repo}
	return &secret{Username: username, Password: password, TmutilURL: u.String()}
}

func passwordOrGenerate(pw string) (string, error) {
	if pw == "" {
		return rand.Text(), nil
	}
	return pw, validatePassword(pw)
}

func (w *web) createCredential(rw http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	var password string
	ok := w.updateRepoWith(rw, r, func(st *State, repo *Repo) error {
		if err := validateUsername(st, username); err != nil {
			return err
		}
		var err error
		if password, err = passwordOrGenerate(r.FormValue("password")); err != nil {
			return err
		}
		c, err := createCredential(st, username, password)
		if err != nil {
			return err
		}
		c.Created = time.Now()
		repo.Credentials = append(repo.Credentials, c)
		return nil
	})
	if ok {
		w.renderRepo(rw, r, http.StatusOK, "", newSecret(w.hostname, r.PathValue("name"), username, password))
	}
}

func findCredential(repo *Repo, username string) (*Credential, error) {
	for _, c := range repo.Credentials {
		if c.Username == username {
			return c, nil
		}
	}
	return nil, errNotFound
}

func (w *web) resetCredential(rw http.ResponseWriter, r *http.Request) {
	username := r.PathValue("user")
	var password string
	ok := w.updateRepoWith(rw, r, func(_ *State, repo *Repo) error {
		if _, err := findCredential(repo, username); err != nil {
			return err
		}
		var err error
		if password, err = passwordOrGenerate(r.FormValue("password")); err != nil {
			return err
		}
		return setSambaPassword(username, password)
	})
	if ok {
		w.renderRepo(rw, r, http.StatusOK, "", newSecret(w.hostname, r.PathValue("name"), username, password))
	}
}

func (w *web) toggleCredential(rw http.ResponseWriter, r *http.Request) {
	name, username := r.PathValue("name"), r.PathValue("user")
	disabled := false
	ok := w.updateRepoWith(rw, r, func(_ *State, repo *Repo) error {
		c, err := findCredential(repo, username)
		if err != nil {
			return err
		}
		c.Enabled = !c.Enabled
		disabled = !c.Enabled
		return nil
	})
	if !ok {
		return
	}
	if disabled {
		closeShare(name)
	}
	http.Redirect(rw, r, "/repos/"+name, http.StatusSeeOther) //nolint:gosec // same-origin path to an existing repo
}

func (w *web) deleteCredential(rw http.ResponseWriter, r *http.Request) {
	name, username := r.PathValue("name"), r.PathValue("user")
	ok := w.updateRepoWith(rw, r, func(_ *State, repo *Repo) error {
		c, err := findCredential(repo, username)
		if err != nil {
			return err
		}
		if err := deleteUser(c.Username); err != nil {
			log.Printf("delete user %s: %v", c.Username, err)
		}
		for i, cc := range repo.Credentials {
			if cc == c {
				repo.Credentials = append(repo.Credentials[:i], repo.Credentials[i+1:]...)
				break
			}
		}
		return nil
	})
	if !ok {
		return
	}
	closeShare(name)
	http.Redirect(rw, r, "/repos/"+name, http.StatusSeeOther) //nolint:gosec // same-origin path to an existing repo
}

// ---- formatting ----

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}
