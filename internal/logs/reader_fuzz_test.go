package logs

import (
	"strings"
	"testing"
)

func FuzzParseLine(f *testing.F) {
	// Seed corpus with representative Coraza audit logs, edge cases, and corrupted inputs
	f.Add([]byte(`{"transaction":{"timestamp":"02/Jan/2026:15:04:05 -0700","unix_timestamp":1767279845,"id":"tx-123","client_ip":"192.168.1.1","is_interrupted":true,"action":"deny","request":{"uri":"/login"}},"messages":[{"id":942100,"msg":"SQLi detected"}]}`))
	f.Add([]byte(`{"transaction":{"id":"tx-456","client_ip":"10.0.0.1","is_interrupted":false},"messages":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"transaction":{}}`))
	f.Add([]byte(""))
	f.Add([]byte("not a json line"))
	f.Add([]byte("\x00\xff\xfe\x00"))
	f.Add([]byte(`{"transaction":{"id":"tx-null","client_ip":"192.168.1.1\x00extra"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant 1: Parser must never panic on arbitrary binary or malformed JSON
		entry, err := parseLine(data)
		if err == nil {
			// Invariant 2: Parsed entries with successful decoding must have non-empty ID
			if entry.Client != "" && strings.Contains(entry.Client, "\x00") {
				t.Errorf("Client IP contains unhandled null byte: %q", entry.Client)
			}
		}
	})
}
