package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// certReloadInterval bounds how often the keypair is stat'ed. Certificate
// rotation is a minutes-to-days event, so checking at most once a minute is
// ample and keeps the TLS handshake path off the filesystem.
const certReloadInterval = time.Minute

// certReloader serves a TLS keypair read from disk, picking up changes without
// a restart.
//
// This matters for any setup that rotates the certificate in place: cert-manager
// writing a renewed certificate into the mounted Secret, or an operator swapping
// the files on a systemd host. http.Server.ListenAndServeTLS(cert, key) reads
// the pair exactly once at startup, so without this the server would keep
// serving an expired certificate until something restarted it.
//
// Kubernetes updates a mounted Secret by swapping the ..data symlink, so both
// the modification time and the size of the visible path change; that is what
// is compared here.
type certReloader struct {
	certPath string
	keyPath  string
	interval time.Duration

	mu        sync.RWMutex
	cert      *tls.Certificate
	stamp     string    // fingerprint of the files behind cert
	lastCheck time.Time // when the files were last stat'ed
}

// newCertReloader loads the keypair once so that a bad path or an unreadable
// key is reported at startup rather than on the first connection.
func newCertReloader(certPath, keyPath string, interval time.Duration) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath, interval: interval}

	cert, stamp, err := r.load()
	if err != nil {
		return nil, err
	}
	r.cert = cert
	r.stamp = stamp
	r.lastCheck = time.Now()

	return r, nil
}

// load reads the keypair and returns it with a fingerprint of the source files.
func (r *certReloader) load() (*tls.Certificate, string, error) {
	stamp, err := r.fingerprint()
	if err != nil {
		return nil, "", err
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("loading TLS keypair (%s, %s): %w", r.certPath, r.keyPath, err)
	}

	return &cert, stamp, nil
}

// fingerprint identifies the current contents of both files by size and
// modification time, which is enough to notice a rotation without reading them.
func (r *certReloader) fingerprint() (string, error) {
	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return "", fmt.Errorf("stat TLS certificate %s: %w", r.certPath, err)
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return "", fmt.Errorf("stat TLS key %s: %w", r.keyPath, err)
	}

	return fmt.Sprintf("%d/%d/%d/%d",
		certInfo.Size(), certInfo.ModTime().UnixNano(),
		keyInfo.Size(), keyInfo.ModTime().UnixNano()), nil
}

// GetCertificate is the tls.Config.GetCertificate callback.
//
// It never fails a handshake because of a reload problem: if the files have
// become unreadable or inconsistent — which is the normal transient state while
// something rewrites them — the previously loaded certificate keeps being
// served and the error is logged.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, lastCheck := r.cert, r.lastCheck
	r.mu.RUnlock()

	if time.Since(lastCheck) < r.interval {
		return cert, nil
	}

	return r.refresh(), nil
}

// refresh re-stats the keypair and reloads it if it changed, returning the
// certificate to serve.
func (r *certReloader) refresh() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Another goroutine may have refreshed while this one waited for the lock.
	if time.Since(r.lastCheck) < r.interval {
		return r.cert
	}
	r.lastCheck = time.Now()

	stamp, err := r.fingerprint()
	if err != nil {
		log.Printf("TLS certificate reload: %v (continuing with the loaded certificate)", err)
		return r.cert
	}
	if stamp == r.stamp {
		return r.cert
	}

	cert, stamp, err := r.load()
	if err != nil {
		// A rotation is not atomic across two files, so a mismatched pair here
		// is expected to be transient; the next check picks it up.
		log.Printf("TLS certificate reload: %v (continuing with the loaded certificate)", err)
		return r.cert
	}

	r.cert = cert
	r.stamp = stamp
	log.Printf("TLS certificate reloaded from %s", r.certPath)

	return r.cert
}

// tlsConfig returns a TLS config that serves the reloaded keypair.
func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}
