// Package server exposes the two planes of design.md §1: the mTLS network
// data-plane (generate/unwrap/health only) and the local Unix-socket
// control-plane.
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/darinehgroup/kms/internal/core"
	"github.com/darinehgroup/kms/internal/kcrypto"
)

// maxBodyBytes caps data-plane request bodies (§6 fix). Real requests are
// under 200 bytes.
const maxBodyBytes = 16 << 10

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: code, Message: msg})
}

// writeCoreErr maps core errors onto the §6 error contract.
func writeCoreErr(w http.ResponseWriter, err error) {
	var inv *core.InvalidError
	switch {
	case errors.As(err, &inv):
		writeErr(w, http.StatusBadRequest, "INVALID_REQUEST", inv.Msg)
	case errors.Is(err, core.ErrSealed):
		writeErr(w, http.StatusServiceUnavailable, "SEALED", "service is sealed")
	case errors.Is(err, core.ErrRateLimited):
		writeErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded for this company_id")
	case errors.Is(err, core.ErrKEKVersionUnknown):
		writeErr(w, http.StatusBadRequest, "KEK_VERSION_UNKNOWN", "requested kek_version does not exist")
	case errors.Is(err, core.ErrUnwrapFailed):
		writeErr(w, http.StatusBadRequest, "UNWRAP_FAILED", "unwrap failed")
	default:
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body")
		return false
	}
	return true
}

// NewDataPlaneHandler serves exactly the three §6 endpoints.
func NewDataPlaneHandler(svc *core.Service) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		if svc.Sealed() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "sealed", "sealed": true})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "sealed": false})
	})

	mux.HandleFunc("POST /v1/dek/generate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CompanyID string `json:"company_id"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		wrapped, version, dek, err := svc.GenerateDEK(req.CompanyID)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"wrapped_dek":   base64.StdEncoding.EncodeToString(wrapped),
			"kek_version":   version,
			"plaintext_dek": base64.StdEncoding.EncodeToString(dek),
		})
		kcrypto.Zero(dek)
	})

	mux.HandleFunc("POST /v1/dek/unwrap", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CompanyID  string `json:"company_id"`
			WrappedDEK string `json:"wrapped_dek"`
			KEKVersion int64  `json:"kek_version"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		wrapped, err := base64.StdEncoding.DecodeString(req.WrappedDEK)
		if err != nil {
			// A non-decodable blob is a corrupted blob: same generic error
			// as any other unwrap failure (§6, no oracle).
			writeErr(w, http.StatusBadRequest, "UNWRAP_FAILED", "unwrap failed")
			return
		}
		dek, err := svc.UnwrapDEK(req.CompanyID, wrapped, req.KEKVersion)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"plaintext_dek": base64.StdEncoding.EncodeToString(dek),
		})
		kcrypto.Zero(dek)
	})

	return mux
}
