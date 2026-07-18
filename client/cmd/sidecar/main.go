// Command sidecar is the local sidecar form: the client core wrapped as a
// localhost OpenAI-compatible proxy. Run it and point any OpenAI SDK at it via
// base_url; it seals the sensitive request fields to the provider and opens the
// sealed response, so your app keeps talking plain OpenAI.
//
// The provider's encryption key and signer address are passed in as flags for
// now (attestation — verifying them out of a TEE quote — is a later step).
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/0gfoundation/0g-pc/client/core"
	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

func main() {
	listen := flag.String("listen", "localhost:8787", "address to listen on")
	providerURL := flag.String("provider-url", "", "provider (router/broker) OpenAI endpoint")
	encPubB64 := flag.String("provider-enc-key", "", "provider HPKE public key, base64url (attestation stub)")
	signer := flag.String("provider-signer", "", "provider on-chain signer address (0x...)")
	flag.Parse()

	if *providerURL == "" || *encPubB64 == "" || *signer == "" {
		log.Fatal("provider-url, provider-enc-key and provider-signer are all required")
	}
	encPub, err := base64.RawURLEncoding.DecodeString(*encPubB64)
	if err != nil {
		log.Fatalf("bad provider-enc-key: %v", err)
	}

	client := core.New(core.Provider{
		URL:        *providerURL,
		EncPubKey:  crypto.PublicKey(encPub),
		SignerAddr: *signer,
	})
	log.Printf("sidecar listening on %s -> %s", *listen, *providerURL)
	if err := http.ListenAndServe(*listen, newHandler(client)); err != nil {
		log.Fatal(err)
	}
}

// newHandler is the OpenAI-compatible proxy over the client core. It is split
// out from main so tests can drive it with httptest.
func newHandler(c *core.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "read request body")
			return
		}
		var req wire.Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "request body is not a JSON object")
			return
		}
		resp, err := c.Complete(r.Context(), req)
		if err != nil {
			// Seal/transport/open failure — upstream-facing, so 502.
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode response")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	return mux
}

// writeError emits an OpenAI-shaped error object.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg},
	})
}
