package udpframe

import (
	"bytes"
	"io"
	"testing"
)

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, d := range [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte{7}, MaxDatagram)} {
		if err := Write(&buf, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := Write(&buf, make([]byte, MaxDatagram+1)); err == nil {
		t.Error("oversized datagram written")
	}
	r := NewReader(&buf)
	for _, want := range []int{5, 0, MaxDatagram} {
		d, err := r.Read()
		if err != nil || len(d) != want {
			t.Fatalf("read %d bytes, %v; want %d", len(d), err, want)
		}
	}
	if _, err := r.Read(); err != io.EOF {
		t.Errorf("end: %v", err)
	}
	if _, err := NewReader(bytes.NewReader([]byte{0, 9, 1})).Read(); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated: %v", err)
	}
}
