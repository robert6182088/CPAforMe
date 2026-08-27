package api

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// ValidateTLSConfig verifies TLS files before a hot listener reload tears down
// the currently working listener.
func ValidateTLSConfig(cfg *config.Config, configFilePath string) error {
	_, err := loadServerTLSCertificate(cfg, configFilePath)
	return err
}

func loadServerTLSCertificate(cfg *config.Config, configFilePath string) (tls.Certificate, error) {
	if cfg == nil || !cfg.TLS.Enable {
		return tls.Certificate{}, nil
	}

	certPath := resolveServerFilePath(cfg.TLS.Cert, configFilePath)
	keyPath := resolveServerFilePath(cfg.TLS.Key, configFilePath)
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("tls.cert or tls.key is empty")
	}

	certPair, errLoad := tls.LoadX509KeyPair(certPath, keyPath)
	if errLoad != nil {
		return tls.Certificate{}, errLoad
	}
	return certPair, nil
}

func resolveServerFilePath(rawPath string, configFilePath string) string {
	pathValue := strings.TrimSpace(rawPath)
	if pathValue == "" {
		return ""
	}
	if strings.HasPrefix(pathValue, "~/") || strings.HasPrefix(pathValue, `~\`) {
		if userHome, errHome := os.UserHomeDir(); errHome == nil && userHome != "" {
			return filepath.Join(userHome, strings.TrimLeft(pathValue[2:], `/\`))
		}
	}
	if filepath.IsAbs(pathValue) {
		return pathValue
	}
	configDir := filepath.Dir(configFilePath)
	if configFilePath == "" || configDir == "." {
		return pathValue
	}
	return filepath.Join(configDir, pathValue)
}
