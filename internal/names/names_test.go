package names

import (
	"errors"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	c := NewChecker([]string{"Internal"})
	for name, want := range map[string]error{
		"myapp":                 nil,
		"a":                     nil,
		"my-app-2":              nil,
		strings.Repeat("a", 63): nil,
		strings.Repeat("a", 64): ErrInvalid,
		"-app":                  ErrInvalid,
		"app-":                  ErrInvalid,
		"my_app":                ErrInvalid,
		"MyApp":                 ErrInvalid,
		"a.b":                   ErrInvalid,
		"":                      ErrInvalid,
		"xn--80ak6aa92e":        ErrPunycode,
		"www":                   ErrReserved,
		"internal":              ErrReserved,
	} {
		if got := c.Check(name); !errors.Is(got, want) {
			t.Errorf("Check(%q) = %v, want %v", name, got, want)
		}
	}
	if Normalize("  MyApp ") != "myapp" {
		t.Error("Normalize")
	}
}
