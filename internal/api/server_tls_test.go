package api

import (
	"path/filepath"
	"testing"
)

func TestResolveServerFilePathUsesConfigDirectory(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	got := resolveServerFilePath(filepath.Join("certs", "server.pem"), configPath)
	want := filepath.Join(filepath.Dir(configPath), "certs", "server.pem")
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestResolveServerFilePathKeepsAbsolutePath(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "server.pem")
	got := resolveServerFilePath(absolute, filepath.Join(t.TempDir(), "config.yaml"))
	if got != absolute {
		t.Fatalf("resolved path = %q, want %q", got, absolute)
	}
}
