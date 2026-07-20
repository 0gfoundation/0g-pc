package core

import (
	"io"
	"strings"
	"testing"
)

func TestSSEReader(t *testing.T) {
	// Comments (: ...), other fields (event:), and blank-line separators are all
	// handled; only data payloads come back.
	in := "data: {\"a\":1}\n\n" +
		": a comment\ndata: {\"b\":2}\n\n" +
		"event: x\ndata: {\"c\":3}\n\n" +
		"data: [DONE]\n\n"
	r := newSSEReader(strings.NewReader(in))

	var got []string
	for {
		d, err := r.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		got = append(got, string(d))
	}
	want := []string{`{"a":1}`, `{"b":2}`, `{"c":3}`, "[DONE]"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSSEReaderFinalEventNoTrailingBlank(t *testing.T) {
	r := newSSEReader(strings.NewReader("data: {\"x\":1}")) // no trailing blank line
	d, err := r.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if string(d) != `{"x":1}` {
		t.Fatalf("got %q", d)
	}
	if _, err := r.next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}
