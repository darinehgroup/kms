package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/darinehgroup/kms/internal/core"
	"github.com/darinehgroup/kms/internal/kcrypto"
	"github.com/darinehgroup/kms/internal/totp"
)

// TOTPIssuer names the KMS in otpauth enrollment URIs.
const TOTPIssuer = "Finomix-KMS"

// writeAdminErr maps core errors to control-plane responses. Unlike the
// data-plane, messages here may be specific — the caller is a founder on a
// local socket, not a network peer.
func writeAdminErr(w http.ResponseWriter, err error) {
	var inv *core.InvalidError
	status, code := http.StatusInternalServerError, "INTERNAL"
	switch {
	case errors.As(err, &inv):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	case errors.Is(err, core.ErrSealed):
		status, code = http.StatusServiceUnavailable, "SEALED"
	case errors.Is(err, core.ErrAlreadySealed), errors.Is(err, core.ErrAlreadyUnsealed):
		status, code = http.StatusConflict, "CONFLICT"
	case errors.Is(err, core.ErrNotInitialized):
		status, code = http.StatusConflict, "NOT_INITIALIZED"
	case errors.Is(err, core.ErrBadPassphrase):
		status, code = http.StatusForbidden, "BAD_PASSPHRASE"
	case errors.Is(err, core.ErrTOTPDenied):
		status, code = http.StatusForbidden, "TOTP_DENIED"
	case errors.Is(err, core.ErrKEKVersionUnknown):
		status, code = http.StatusBadRequest, "KEK_VERSION_UNKNOWN"
	case errors.Is(err, core.ErrUnwrapFailed):
		status, code = http.StatusBadRequest, "UNWRAP_FAILED"
	}
	writeErr(w, status, code, err.Error())
}

// NewAdminHandler serves the control-plane commands over the Unix socket.
func NewAdminHandler(svc *core.Service) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := svc.Status()
		if err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	})

	mux.HandleFunc("POST /admin/unseal", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ShareA string `json:"share_a"`
			ShareB string `json:"share_b"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if err := svc.Unseal([]byte(req.ShareA), []byte(req.ShareB)); err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sealed": false})
	})

	mux.HandleFunc("POST /admin/seal", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Seal(); err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sealed": true})
	})

	mux.HandleFunc("POST /admin/rotate-kek", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ShareA string `json:"share_a"`
			ShareB string `json:"share_b"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		newVersion, err := svc.RotateKEK([]byte(req.ShareA), []byte(req.ShareB))
		if err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active_kek_version": newVersion})
	})

	mux.HandleFunc("POST /admin/rekey-passphrase", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OldShareA string `json:"old_share_a"`
			OldShareB string `json:"old_share_b"`
			NewShareA string `json:"new_share_a"`
			NewShareB string `json:"new_share_b"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		err := svc.RekeyPassphrase(
			[]byte(req.OldShareA), []byte(req.OldShareB),
			[]byte(req.NewShareA), []byte(req.NewShareB))
		if err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("POST /admin/set-totp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Label string `json:"label"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		seed, err := svc.SetTOTP(req.Label)
		if err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"label":         req.Label,
			"secret_base32": totp.Base32Secret(seed),
			"otpauth_uri":   totp.ProvisioningURI(TOTPIssuer, req.Label, seed),
		})
		kcrypto.Zero(seed)
	})

	mux.HandleFunc("POST /admin/break-glass", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CompanyID  string `json:"company_id"`
			WrappedDEK string `json:"wrapped_dek"`
			KEKVersion int64  `json:"kek_version"`
			TOTPA      string `json:"totp_a"`
			TOTPB      string `json:"totp_b"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		wrapped, err := base64.StdEncoding.DecodeString(req.WrappedDEK)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "INVALID_REQUEST", "wrapped_dek is not valid base64")
			return
		}
		dek, err := svc.BreakGlass(req.CompanyID, wrapped, req.KEKVersion, req.TOTPA, req.TOTPB)
		if err != nil {
			writeAdminErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"plaintext_dek": base64.StdEncoding.EncodeToString(dek),
		})
		kcrypto.Zero(dek)
	})

	return mux
}

// ListenUnix binds the control-plane socket with owner-only permissions
// (design.md §10): directory 0700, socket 0600.
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("server: create socket dir: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("server: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("server: listen unix: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("server: chmod socket: %w", err)
	}
	return ln, nil
}
