package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// benchInfo mirrors the request-sealing usage (SPEC §5.2) for the setup benches.
var benchInfo = []byte("0g-pc/v1/seal")

// benchSizes are representative sealed-payload sizes: a small chat prompt up
// through a large multi-turn context or tool payload. The AEAD cost scales with
// these; the HPKE handshake does not.
var benchSizes = []int{1 << 10, 16 << 10, 256 << 10, 1 << 20}

func sizeName(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func benchBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// BenchmarkSetupSender measures the sender-side HPKE handshake — an X25519
// ephemeral keygen plus the encap DH. This is the dominant per-request CPU cost
// (one setup per SealRequest); the AEAD passes below are comparatively free.
func BenchmarkSetupSender(b *testing.B) {
	_, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := SetupSender(pub, benchInfo); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSetupReceiver measures the receiver-side handshake (the decap DH),
// the matching per-request cost paid by the enclave opening a request.
func BenchmarkSetupReceiver(b *testing.B) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	enc, _, err := SetupSender(pub, benchInfo)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SetupReceiver(priv, enc, benchInfo); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSeal measures a full one-shot seal (HPKE setup + AEAD) across payload
// sizes — the realistic cost of sealing one request. SetBytes reports MB/s;
// compare against BenchmarkSealAEAD to separate the fixed handshake from the
// size-dependent AEAD.
func BenchmarkSeal(b *testing.B) {
	_, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	aad := []byte("model=gpt-4o")
	for _, n := range benchSizes {
		pt := benchBytes(n)
		b.Run(sizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Seal(pub, pt, aad, benchInfo); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpen measures a full one-shot open (HPKE setup + AEAD). Each call
// sets up a fresh receiver at sequence 0, so opening the same sealed message
// repeatedly is valid and isolates the open path from sealing.
func BenchmarkOpen(b *testing.B) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	aad := []byte("model=gpt-4o")
	for _, n := range benchSizes {
		sealed, err := Seal(pub, benchBytes(n), aad, benchInfo)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(sizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Open(priv, sealed, aad, benchInfo); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSealAEAD isolates the symmetric per-frame cost: one Sealer is set up
// once and reused (exactly as streaming does — one HPKE context, many frames),
// so the timed loop is ChaCha20-Poly1305 only, no keygen. This is the marginal
// cost of each additional streamed frame after the handshake.
func BenchmarkSealAEAD(b *testing.B) {
	_, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	aad := []byte("model=gpt-4o")
	for _, n := range benchSizes {
		pt := benchBytes(n)
		_, sealer, err := SetupSender(pub, benchInfo)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(sizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sealer.Seal(pt, aad); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSealParallel runs full one-shot seals across all GOMAXPROCS cores to
// confirm the crypto scales with cores (no shared state / lock contention). Use
// it to estimate seals/sec on an N-core box: roughly N × the single-core rate.
func BenchmarkSealParallel(b *testing.B) {
	_, pub, err := GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	pt := benchBytes(4 << 10)
	aad := []byte("model=gpt-4o")
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Seal(pub, pt, aad, benchInfo); err != nil {
				b.Fatal(err)
			}
		}
	})
}
