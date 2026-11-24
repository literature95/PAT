package util

import (
	"strings"
	"testing"
)

func TestSafeTextStripsTerminalControl(t *testing.T) {
	hostile := "\x1b]0;pwned\x07[link=file:///etc/passwd]click[/link]\x1b[31mRED\x1b[0m\x00tail"
	out := SafeText(hostile, 0)
	for _, bad := range []string{"\x1b", "\x00", "\x07"} {
		if strings.Contains(out, bad) {
			t.Fatalf("control character survived: %q in %q", bad, out)
		}
	}
	if !strings.Contains(out, "RED") || !strings.Contains(out, "[link=") {
		t.Fatalf("visible text was lost: %q", out)
	}
}

func TestSafeTextTruncates(t *testing.T) {
	out := SafeText(strings.Repeat("a", 1000), 50)
	if len([]rune(out)) > 200 || !strings.Contains(out, "truncated") {
		t.Fatalf("did not truncate: %q", out)
	}
}

func TestMarkupEscape(t *testing.T) {
	out := MarkupEscape("[CVE-2021-44208]")
	if out != `\[CVE-2021-44208\]` {
		t.Fatalf("unexpected escape: %q", out)
	}
}

func TestSafeTextKeepsTabsAndNewlines(t *testing.T) {
	out := SafeText("a\tb\nc", 0)
	if out != "a\tb\nc" {
		t.Fatalf("legitimate whitespace lost: %q", out)
	}
}
