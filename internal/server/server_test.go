package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darinehgroup/kms/internal/audit"
	"github.com/darinehgroup/kms/internal/core"
	"github.com/darinehgroup/kms/internal/store"
)

var (
	shareA = []byte("founder-a-share-secret")
	shareB = []byte("founder-b-share-secret")
)

func newService(t *testing.T, unseal bool) *core.Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	aud := audit.New(st.DB())
	if err := core.Init(st, aud, shareA, shareB); err != nil {
		t.Fatal(err)
	}
	svc := core.New(st, aud, 1000)
	if unseal {
		if err := svc.Unseal(shareA, shareB); err != nil {
			t.Fatal(err)
		}
	}
	return svc
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := ts.Client().Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("%s: non-JSON response: %v", path, err)
	}
	return resp, m
}

func TestHealthSealedAndUnsealed(t *testing.T) {
	sealedSrv := httptest.NewServer(NewDataPlaneHandler(newService(t, false)))
	defer sealedSrv.Close()
	resp, err := http.Get(sealedSrv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sealed health status = %d, want 503", resp.StatusCode)
	}

	openSrv := httptest.NewServer(NewDataPlaneHandler(newService(t, true)))
	defer openSrv.Close()
	resp, err = http.Get(openSrv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unsealed health status = %d, want 200", resp.StatusCode)
	}
}

func TestDataPlaneContract(t *testing.T) {
	ts := httptest.NewServer(NewDataPlaneHandler(newService(t, true)))
	defer ts.Close()

	// generate
	resp, gen := postJSON(t, ts, "/v1/dek/generate", map[string]any{"company_id": "comp-001"})
	if resp.StatusCode != 200 {
		t.Fatalf("generate status = %d: %v", resp.StatusCode, gen)
	}
	wrapped, ok1 := gen["wrapped_dek"].(string)
	dek, ok2 := gen["plaintext_dek"].(string)
	version, ok3 := gen["kek_version"].(float64)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("generate response shape wrong: %v", gen)
	}
	if raw, _ := base64.StdEncoding.DecodeString(wrapped); len(raw) != 61 {
		t.Fatalf("wrapped_dek decodes to %d bytes, want 61", len(raw))
	}

	// unwrap roundtrip
	resp, unw := postJSON(t, ts, "/v1/dek/unwrap", map[string]any{
		"company_id": "comp-001", "wrapped_dek": wrapped, "kek_version": int(version)})
	if resp.StatusCode != 200 {
		t.Fatalf("unwrap status = %d: %v", resp.StatusCode, unw)
	}
	if unw["plaintext_dek"] != dek {
		t.Fatal("unwrap returned a different DEK")
	}

	// oracle-free failures: wrong company, corrupt blob, bad base64 → UNWRAP_FAILED
	for _, body := range []map[string]any{
		{"company_id": "comp-002", "wrapped_dek": wrapped, "kek_version": int(version)},
		{"company_id": "comp-001", "wrapped_dek": base64.StdEncoding.EncodeToString(make([]byte, 61)), "kek_version": int(version)},
		{"company_id": "comp-001", "wrapped_dek": "!!!not-base64!!!", "kek_version": int(version)},
	} {
		resp, e := postJSON(t, ts, "/v1/dek/unwrap", body)
		if resp.StatusCode != 400 || e["error"] != "UNWRAP_FAILED" {
			t.Fatalf("body %v: status=%d error=%v, want 400/UNWRAP_FAILED", body, resp.StatusCode, e["error"])
		}
	}

	// unknown version
	resp, e := postJSON(t, ts, "/v1/dek/unwrap", map[string]any{
		"company_id": "comp-001", "wrapped_dek": wrapped, "kek_version": 42})
	if resp.StatusCode != 400 || e["error"] != "KEK_VERSION_UNKNOWN" {
		t.Fatalf("unknown version: status=%d error=%v", resp.StatusCode, e["error"])
	}

	// invalid company_id
	resp, e = postJSON(t, ts, "/v1/dek/generate", map[string]any{"company_id": "has|pipe"})
	if resp.StatusCode != 400 || e["error"] != "INVALID_REQUEST" {
		t.Fatalf("invalid company: status=%d error=%v", resp.StatusCode, e["error"])
	}

	// malformed JSON
	raw, err := ts.Client().Post(ts.URL+"/v1/dek/generate", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	raw.Body.Close()
	if raw.StatusCode != 400 {
		t.Fatalf("malformed JSON status = %d, want 400", raw.StatusCode)
	}
}

func TestDataPlaneSealedError(t *testing.T) {
	ts := httptest.NewServer(NewDataPlaneHandler(newService(t, false)))
	defer ts.Close()
	resp, e := postJSON(t, ts, "/v1/dek/generate", map[string]any{"company_id": "comp-001"})
	if resp.StatusCode != 503 || e["error"] != "SEALED" {
		t.Fatalf("sealed generate: status=%d error=%v, want 503/SEALED", resp.StatusCode, e["error"])
	}
}

// --- mTLS end-to-end -------------------------------------------------------

type testPKI struct {
	caPEM      []byte
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverCert tls.Certificate
	clientCert tls.Certificate
	clientPin  string
	nextSerial int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test KMS CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	pki := &testPKI{
		caPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caCert:     caCert,
		caKey:      caKey,
		nextSerial: 2,
	}
	pki.serverCert = pki.leaf("kms-server", x509.ExtKeyUsageServerAuth)
	pki.clientCert = pki.leaf("app-client", x509.ExtKeyUsageClientAuth)
	pin := sha256.Sum256(pki.clientCert.Certificate[0])
	pki.clientPin = hex.EncodeToString(pin[:])
	return pki
}

func (p *testPKI) leaf(cn string, eku x509.ExtKeyUsage) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.nextSerial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.nextSerial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMTLSWithPinning(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()

	certPath := writePEM(t, dir, "server.crt", "CERTIFICATE", pki.serverCert.Certificate[0])
	keyDER, err := x509.MarshalECPrivateKey(pki.serverCert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writePEM(t, dir, "server.key", "EC PRIVATE KEY", keyDER)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	tlsCfg, err := BuildTLSConfig(certPath, keyPath, caPath,
		[]string{"SHA256:" + strings.ToUpper(pki.clientPin)}) // exercise pin normalization
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("MinVersion is not TLS 1.3")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: NewDataPlaneHandler(newService(t, true))}
	go srv.Serve(ln)
	defer srv.Close()
	url := fmt.Sprintf("https://%s/v1/health", ln.Addr())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(pki.caPEM)
	newClient := func(cert *tls.Certificate) *http.Client {
		cfg := &tls.Config{RootCAs: caPool, ServerName: "127.0.0.1"}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return &http.Client{
			Transport: &http.Transport{TLSClientConfig: cfg},
			Timeout:   5 * time.Second,
		}
	}

	// Pinned client cert: accepted.
	resp, err := newClient(&pki.clientCert).Get(url)
	if err != nil {
		t.Fatalf("pinned client rejected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health over mTLS = %d, want 200", resp.StatusCode)
	}

	// No client cert: handshake refused.
	if resp, err := newClient(nil).Get(url); err == nil {
		resp.Body.Close()
		t.Fatal("connection without client certificate accepted")
	}

	// A fresh cert signed by the same CA but NOT pinned: refused — the exact
	// mis-issuance scenario the §10 pin check exists for.
	unpinned := pki.leaf("rogue-client", x509.ExtKeyUsageClientAuth)
	if resp, err := newClient(&unpinned).Get(url); err == nil {
		resp.Body.Close()
		t.Fatal("unpinned client certificate accepted")
	}
}

func TestNormalizePin(t *testing.T) {
	want := "aabbcc"
	for _, in := range []string{"aabbcc", "AABBCC", "sha256:aabbcc", " aa:bb:cc "} {
		if got := NormalizePin(in); got != want {
			t.Errorf("NormalizePin(%q) = %q, want %q", in, got, want)
		}
	}
}
