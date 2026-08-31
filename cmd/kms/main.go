// Command kms is the Finomix internal KMS: a single binary providing the
// long-running server (`kms serve`) and the local control-plane commands of
// design.md §1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/darinehgroup/kms/internal/audit"
	"github.com/darinehgroup/kms/internal/config"
	"github.com/darinehgroup/kms/internal/core"
	"github.com/darinehgroup/kms/internal/kcrypto"
	"github.com/darinehgroup/kms/internal/server"
	"github.com/darinehgroup/kms/internal/store"
)

const usage = `Usage: kms <command> [flags]

Server:
  serve             run the KMS server (data-plane mTLS + admin Unix socket)

Bootstrap (direct database access, server not required):
  init              create KEK version 1 and the audit genesis record
  verify-audit      verify the audit log hash chain

Control-plane (talks to the running server via KMS_ADMIN_SOCKET):
  status            show seal state and key/seed counts
  unseal            enter both passphrase shares to unseal
  seal              drop the in-memory keyring
  rotate-kek        create a new KEK version (requires both shares)
  rekey-passphrase  re-encrypt all KEK versions under a new passphrase
  set-totp          enroll a founder TOTP seed      (--label founder_a)
  break-glass       emergency unwrap with two TOTP codes
                    (--company --wrapped-dek --kek-version [--totp-a --totp-b])

Environment: KMS_DB_PATH, KMS_ADMIN_SOCKET, KMS_LISTEN_ADDR,
  KMS_TLS_SERVER_CERT, KMS_TLS_SERVER_KEY, KMS_TLS_CLIENT_CA,
  KMS_TLS_CLIENT_PINS, KMS_RATE_LIMIT_UNWRAP_PER_MIN, KMS_MLOCK
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("kms: ")
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatal(err)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		err = cmdServe(cfg)
	case "init":
		err = cmdInit(cfg)
	case "verify-audit":
		err = cmdVerifyAudit(cfg)
	case "status":
		err = cmdStatus(cfg)
	case "unseal":
		err = cmdUnseal(cfg)
	case "seal":
		err = cmdSeal(cfg)
	case "rotate-kek":
		err = cmdRotateKEK(cfg)
	case "rekey-passphrase":
		err = cmdRekeyPassphrase(cfg)
	case "set-totp":
		err = cmdSetTOTP(cfg, args)
	case "break-glass":
		err = cmdBreakGlass(cfg, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "kms: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func cmdServe(cfg config.Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("KMS_LISTEN_ADDR is required for serve")
	}
	if cfg.TLSServerCert == "" || cfg.TLSServerKey == "" || cfg.TLSClientCA == "" {
		return errors.New("KMS_TLS_SERVER_CERT, KMS_TLS_SERVER_KEY and KMS_TLS_CLIENT_CA are required for serve")
	}
	if cfg.MlockRequested {
		if err := lockMemory(); err != nil {
			log.Printf("warning: mlock failed (%v); continuing without locked memory", err)
		} else {
			log.Printf("process memory locked (mlockall)")
		}
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.InitSchema(); err != nil {
		return err
	}
	initialized, err := st.Initialized()
	if err != nil {
		return err
	}
	if !initialized {
		return core.ErrNotInitialized
	}
	aud := audit.New(st.DB())
	svc := core.New(st, aud, cfg.UnwrapPerMin)

	tlsCfg, err := server.BuildTLSConfig(cfg.TLSServerCert, cfg.TLSServerKey, cfg.TLSClientCA, cfg.TLSClientPins)
	if err != nil {
		return err
	}
	adminLn, err := server.ListenUnix(cfg.AdminSocket)
	if err != nil {
		return err
	}
	adminSrv := &http.Server{
		Handler:           server.NewAdminHandler(svc),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // rotate/rekey run Argon2id per KEK version
		WriteTimeout:      5 * time.Minute,
	}
	dataSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.NewDataPlaneHandler(svc),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("control-plane listening on unix socket %s", cfg.AdminSocket)
		if err := adminSrv.Serve(adminLn); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	go func() {
		log.Printf("data-plane listening on %s (mTLS, TLS 1.3)", cfg.ListenAddr)
		log.Printf("state: sealed — run 'kms unseal' with both founders present")
		if err := dataSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("data server: %w", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
	case err := <-errCh:
		log.Printf("server error: %v, shutting down", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dataSrv.Shutdown(ctx)
	adminSrv.Shutdown(ctx)
	if !svc.Sealed() {
		if err := svc.Seal(); err != nil {
			log.Printf("warning: seal on shutdown: %v", err)
		}
	}
	os.Remove(cfg.AdminSocket)
	return nil
}

func cmdInit(cfg config.Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.InitSchema(); err != nil {
		return err
	}
	fmt.Println("Initializing the KMS: each founder enters their passphrase share.")
	fmt.Println("WARNING: this is a 2-of-2 scheme with no recovery. Losing either")
	fmt.Println("share makes the KEK — and all data encrypted under it — unrecoverable.")
	fmt.Println("Back up each share securely and separately (design.md §8).")
	shareA, err := promptSecretConfirm("Founder A share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareA)
	shareB, err := promptSecretConfirm("Founder B share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareB)
	aud := audit.New(st.DB())
	if err := core.Init(st, aud, shareA, shareB); err != nil {
		return err
	}
	fmt.Println("KMS initialized: KEK version 1 created, audit genesis record written.")
	fmt.Println("Next: start the server (kms serve), unseal it (kms unseal), then")
	fmt.Println("enroll both founders' TOTP seeds (kms set-totp --label founder_a / founder_b).")
	return nil
}

func cmdVerifyAudit(cfg config.Config) error {
	st, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := audit.Verify(st.DB())
	if err != nil {
		return fmt.Errorf("AUDIT CHAIN BROKEN: %w", err)
	}
	fmt.Printf("audit chain OK: %d records verified\n", n)
	return nil
}

func cmdStatus(cfg config.Config) error {
	var st core.Status
	if err := adminCall(cfg.AdminSocket, "GET", "/admin/status", nil, &st); err != nil {
		return err
	}
	fmt.Printf("initialized:        %v\n", st.Initialized)
	fmt.Printf("sealed:             %v\n", st.Sealed)
	if !st.Sealed {
		fmt.Printf("active kek version: %d\n", st.ActiveKEKVersion)
	}
	fmt.Printf("kek versions:       %d\n", st.KEKVersions)
	fmt.Printf("totp seeds:         %d\n", st.TOTPSeeds)
	return nil
}

func cmdUnseal(cfg config.Config) error {
	fmt.Println("Unseal: each founder enters their passphrase share.")
	shareA, err := promptSecret("Founder A share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareA)
	shareB, err := promptSecret("Founder B share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareB)
	req := map[string]string{"share_a": string(shareA), "share_b": string(shareB)}
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/unseal", req, nil); err != nil {
		return err
	}
	fmt.Println("unsealed: data-plane is now serving")
	return nil
}

func cmdSeal(cfg config.Config) error {
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/seal", map[string]string{}, nil); err != nil {
		return err
	}
	fmt.Println("sealed: keyring zeroized, data-plane returns SEALED")
	return nil
}

func cmdRotateKEK(cfg config.Config) error {
	fmt.Println("KEK rotation: both founders re-enter their passphrase shares.")
	shareA, err := promptSecret("Founder A share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareA)
	shareB, err := promptSecret("Founder B share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(shareB)
	req := map[string]string{"share_a": string(shareA), "share_b": string(shareB)}
	var resp struct {
		ActiveKEKVersion int64 `json:"active_kek_version"`
	}
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/rotate-kek", req, &resp); err != nil {
		return err
	}
	fmt.Printf("rotated: KEK version %d is now active; previous versions retired but still unwrap-capable\n", resp.ActiveKEKVersion)
	fmt.Println("reminder: start the App-side gradual rewrap job (design.md §5)")
	return nil
}

func cmdRekeyPassphrase(cfg config.Config) error {
	fmt.Println("Passphrase rekey: enter the OLD shares, then the NEW shares.")
	oldA, err := promptSecret("OLD founder A share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(oldA)
	oldB, err := promptSecret("OLD founder B share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(oldB)
	newA, err := promptSecretConfirm("NEW founder A share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(newA)
	newB, err := promptSecretConfirm("NEW founder B share")
	if err != nil {
		return err
	}
	defer kcrypto.Zero(newB)
	req := map[string]string{
		"old_share_a": string(oldA), "old_share_b": string(oldB),
		"new_share_a": string(newA), "new_share_b": string(newB),
	}
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/rekey-passphrase", req, nil); err != nil {
		return err
	}
	fmt.Println("rekeyed: all KEK versions re-encrypted under the new passphrase")
	return nil
}

func cmdSetTOTP(cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("set-totp", flag.ExitOnError)
	label := fs.String("label", "", "seed label, e.g. founder_a")
	fs.Parse(args)
	if *label == "" {
		return errors.New("--label is required (e.g. --label founder_a)")
	}
	var resp struct {
		Label        string `json:"label"`
		SecretBase32 string `json:"secret_base32"`
		OtpauthURI   string `json:"otpauth_uri"`
	}
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/set-totp",
		map[string]string{"label": *label}, &resp); err != nil {
		return err
	}
	fmt.Printf("TOTP seed enrolled for %q. Shown ONCE — load it into the founder's\n", resp.Label)
	fmt.Println("authenticator app now; it is stored only encrypted under the KEK.")
	fmt.Printf("  secret (base32): %s\n", resp.SecretBase32)
	fmt.Printf("  otpauth URI:     %s\n", resp.OtpauthURI)
	return nil
}

func cmdBreakGlass(cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("break-glass", flag.ExitOnError)
	company := fs.String("company", "", "company_id the DEK belongs to")
	wrapped := fs.String("wrapped-dek", "", "base64 wrapped_dek from the App database")
	kekVersion := fs.Int64("kek-version", 0, "kek_version stored alongside the wrapped_dek")
	totpA := fs.String("totp-a", "", "current TOTP code of founder A")
	totpB := fs.String("totp-b", "", "current TOTP code of founder B")
	fs.Parse(args)
	if *company == "" || *wrapped == "" || *kekVersion < 1 {
		return errors.New("--company, --wrapped-dek and --kek-version are required")
	}
	if *totpA == "" {
		code, err := promptLine("Founder A TOTP code")
		if err != nil {
			return err
		}
		*totpA = code
	}
	if *totpB == "" {
		code, err := promptLine("Founder B TOTP code")
		if err != nil {
			return err
		}
		*totpB = code
	}
	req := map[string]any{
		"company_id":  *company,
		"wrapped_dek": *wrapped,
		"kek_version": *kekVersion,
		"totp_a":      *totpA,
		"totp_b":      *totpB,
	}
	var resp struct {
		PlaintextDEK string `json:"plaintext_dek"`
	}
	if err := adminCall(cfg.AdminSocket, "POST", "/admin/break-glass", req, &resp); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "break-glass unwrap succeeded — this access is permanently recorded in the audit log")
	fmt.Println(resp.PlaintextDEK)
	return nil
}
