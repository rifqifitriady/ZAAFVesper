package winproc

import (
	"reflect"
	"testing"
	"time"
)

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{``, nil},
		{`cmd.exe`, []string{"cmd.exe"}},
		{`"C:\Program Files\x.exe" /a "b c"`, []string{`C:\Program Files\x.exe`, "/a", "b c"}},
		// Examples from the Microsoft C runtime documentation.
		{`p "a b c" d e`, []string{"p", "a b c", "d", "e"}},
		{`p "ab\"c" "\\" d`, []string{"p", `ab"c`, `\`, "d"}},
		{`p a\\\b d"e f"g h`, []string{"p", `a\\\b`, "de fg", "h"}},
		{`p a\\\"b c d`, []string{"p", `a\"b`, "c", "d"}},
		{`p a\\\\"b c" d e`, []string{"p", `a\\b c`, "d", "e"}},
		{`p "a""b"`, []string{"p", `a"b`}},
		{`C:\Windows\System32\cmd.exe /c whoami`, []string{`C:\Windows\System32\cmd.exe`, "/c", "whoami"}},
	}
	for _, c := range cases {
		if got := SplitCommandLine(c.in, 0); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitCommandLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := SplitCommandLine("a b c d", 2); len(got) != 2 {
		t.Errorf("max: %q", got)
	}
}

func TestFiletimeToTime(t *testing.T) {
	if got := FiletimeToTime(FiletimeEpochDelta + 10_000_000); !got.Equal(time.Unix(1, 0)) {
		t.Fatalf("got %v", got)
	}
	if !FiletimeToTime(5).IsZero() {
		t.Fatal("pre-1970 must be zero")
	}
}

func FuzzSplitCommandLine(f *testing.F) {
	f.Add(`"a b" c\\"d`)
	f.Fuzz(func(t *testing.T, s string) {
		for _, a := range SplitCommandLine(s, 64) {
			if len(a) > len(s) {
				t.Fatalf("arg longer than input")
			}
		}
	})
}
