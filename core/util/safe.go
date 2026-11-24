// Package util contains the single chokepoint for untrusted tool output.
// Store raw output; sanitize only at render/emit time (Cerno §8 pattern).
package util

import (
	"regexp"
	"strings"
	)

var (
	ansiCSI  = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSC  = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	ansiTwo  = regexp.MustCompile(`\x1b[@-_]`)
	controls = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

// SafeText removes terminal escape sequences and control characters (keeping
// tab and newline), then truncates to max runes. It is the only sanctioned way
// to render MSF/nmap output in the TUI, events and audit exports.
func SafeText(s string, max int) string {
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	s = ansiTwo.ReplaceAllString(s, "")
	s = controls.ReplaceAllString(s, "")
	if max > 0 {
		r := []rune(s)
		if len(r) > max {
			return string(r[:max]) + "\n… [truncated " + itoa(len(r)-max) + " runes]"
		}
	}
	return s
}

// MarkupEscape additionally neutralizes square brackets for markup parsers.
// Apply after SafeText. Not idempotent by design (Cerno regression pin).
func MarkupEscape(s string) string {
	s = strings.ReplaceAll(s, "[", `\[`)
	s = strings.ReplaceAll(s, "]", `\]`)
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
