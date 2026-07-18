package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

// Provider identifies the enclave the client seals to. In production EncPubKey
// and SignerAddr are extracted from a verified attestation quote; here they are
// supplied directly — attestation is a later step.
type Provider struct {
	URL        string           // OpenAI-shaped endpoint (router or broker)
	EncPubKey  crypto.PublicKey // provider HPKE recipient key
	SignerAddr string           // provider on-chain signer address; used as the pin
}

// Client is the shared client core: it seals a request's sensitive fields to
// the provider, sends the envelope, and opens the sealed response. It holds no
// server of its own — the sidecar, the cloud-TEE gateway, and the in-process
// SDK all wrap this.
type Client struct {
	provider Provider
	http     *http.Client
}

// New returns a Client for the given provider, using http.DefaultClient.
func New(p Provider) *Client {
	return &Client{provider: p, http: http.DefaultClient}
}

// Complete performs one non-streaming chat completion. req and the result are
// OpenAI-shaped JSON objects; the sensitive fields are sealed on the way out and
// the sealed response is opened on the way back, so the caller only ever handles
// plaintext.
func (c *Client) Complete(ctx context.Context, req wire.Request) (wire.Response, error) {
	// Fresh ephemeral keypair per request; the enclave seals the response to the
	// public half (§7) and we keep the private half to open it.
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sealed, err := wire.SealRequest(c.provider.EncPubKey, req, sealedFieldsFor(req), c.provider.SignerAddr, ephPub)
	if err != nil {
		return nil, fmt.Errorf("seal request: %w", err)
	}

	respBody, err := c.post(ctx, sealed)
	if err != nil {
		return nil, err
	}

	var sealedResp wire.Response
	if err := json.Unmarshal(respBody, &sealedResp); err != nil {
		return nil, fmt.Errorf("decode sealed response: %w", err)
	}
	out, err := wire.OpenResponse(ephPriv, sealedResp)
	if err != nil {
		return nil, fmt.Errorf("open response: %w", err)
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, env wire.Request) ([]byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post to provider: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read provider response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

// sealedFieldsFor picks the default sensitive fields that are actually present
// in req. A valid chat request always carries "messages"; "tools" often is
// absent. Filtering by presence seals the prompt (and the tool definitions when
// sent) without erroring on a tools-less request, while keeping the default set
// defined in exactly one place (wire.DefaultSealedFields).
func sealedFieldsFor(req wire.Request) []string {
	var fs []string
	for _, f := range wire.DefaultSealedFields() {
		if _, ok := req[f]; ok {
			fs = append(fs, f)
		}
	}
	return fs
}
