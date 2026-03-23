package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestRunHashPasswordWithPasswordFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runHashPassword([]string{"--password", "MyStrongPassword", "--cost", "10"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runHashPassword returned error: %v", err)
	}

	hash := strings.TrimSpace(stdout.String())
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("MyStrongPassword")); err != nil {
		t.Fatalf("hash does not match password: %v", err)
	}
}

func TestRunHashPasswordWithStdin(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runHashPassword([]string{"--stdin"}, strings.NewReader("FromStdinPassword\n"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runHashPassword returned error: %v", err)
	}

	hash := strings.TrimSpace(stdout.String())
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("FromStdinPassword")); err != nil {
		t.Fatalf("hash does not match stdin password: %v", err)
	}
}

func TestRunHashPasswordValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing input source",
			args: []string{},
		},
		{
			name: "both sources specified",
			args: []string{"--stdin", "--password", "x"},
		},
		{
			name: "invalid cost",
			args: []string{"--password", "x", "--cost", "100"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if err := runHashPassword(tt.args, strings.NewReader(""), &stdout, &stderr); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
