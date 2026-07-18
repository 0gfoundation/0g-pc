// Package integration hosts in-process integration tests that exercise the
// protocol layers together (crypto + request envelope + response envelope) by
// playing both the client and the provider-enclave ("broker") roles.
//
// These are integration tests, not end-to-end: everything runs in one process
// with a fake enclave and a fake model — there is no sidecar process, no HTTP,
// no router, and no real TEE. A true e2e test drives the real sidecar binary
// over localhost through to a real broker, and belongs with the client once it
// exists.
package integration
