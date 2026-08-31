package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// adminCall performs one control-plane request over the Unix socket.
// Non-2xx responses are turned into errors carrying the server's message.
func adminCall(socket, method, path string, req, resp any) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		// rotate-kek / rekey-passphrase run Argon2id once per KEK version.
		Timeout: 5 * time.Minute,
	}
	var body io.Reader
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequest(method, "http://kms"+path, body)
	if err != nil {
		return err
	}
	if req != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cannot reach the KMS server on %s (is 'kms serve' running?): %w", socket, err)
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return err
	}
	if httpResp.StatusCode/100 != 2 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s: %s", e.Error, e.Message)
		}
		return fmt.Errorf("server returned HTTP %d", httpResp.StatusCode)
	}
	if resp != nil {
		if err := json.Unmarshal(data, resp); err != nil {
			return fmt.Errorf("decode server response: %w", err)
		}
	}
	return nil
}
