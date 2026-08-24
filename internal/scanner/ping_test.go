package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Turning the scanner on used to be checked only for a non-empty address, so a
// wrong host or port surfaced as uploads that never became CLEAN -- which
// blocks submission -- and then as a queue alarm, long after the setting was
// saved.
func TestPingAnswersWhatIsAtTheAddress(t *testing.T) {
	cases := []struct {
		name  string
		reply string
		ok    bool
	}{
		{"clamd answers", "PONG\x00", true},
		{"something else is listening", "HTTP/1.1 400 Bad Request\r\n", false},
		{"nothing is said", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 16)
				_, _ = conn.Read(buf)
				if tc.reply != "" {
					_, _ = conn.Write([]byte(tc.reply))
				}
			}()
			reply, err := Ping(listener.Addr().String(), 2*time.Second)
			if tc.ok {
				if err != nil {
					t.Fatalf("a clamd that answered PONG was reported as %v", err)
				}
				if !strings.EqualFold(reply, "PONG") {
					t.Errorf("reply = %q", reply)
				}
				return
			}
			if err == nil {
				t.Fatalf("a service that is not clamd was accepted (reply %q)", reply)
			}
		})
	}

	// A port with nothing behind it has to fail quickly rather than hang.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	_ = closed.Close()
	started := time.Now()
	if _, err := Ping(address, 2*time.Second); err == nil {
		t.Error("a closed port was reported as a working scanner")
	}
	if time.Since(started) > 3*time.Second {
		t.Errorf("the check took %v; an administrator is waiting on this", time.Since(started))
	}

	if _, err := Ping("  ", time.Second); err == nil {
		t.Error("an empty address was accepted")
	}
}
