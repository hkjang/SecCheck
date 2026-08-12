package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const Name = "SecCheck"

type Config struct {
	PostgresDSN            string
	BootstrapAdmin         string
	BootstrapAdminPassword string
	EncryptionKey          []byte
	Version                string
	ListenAddr             string
	WebDir                 string
	DataDir                string
}

func LoadConfig() (Config, error) {
	c := Config{
		PostgresDSN:            strings.TrimSpace(os.Getenv("POSTGRES_DSN")),
		BootstrapAdmin:         strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN")),
		BootstrapAdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
		Version:                "dev",
		ListenAddr:             ":8080",
		WebDir:                 "web/dist",
		DataDir:                "data",
	}
	if c.PostgresDSN == "" || c.BootstrapAdmin == "" || c.BootstrapAdminPassword == "" {
		return c, errors.New("POSTGRES_DSN, BOOTSTRAP_ADMIN and BOOTSTRAP_ADMIN_PASSWORD are required")
	}
	if len(c.BootstrapAdminPassword) < 12 {
		return c, errors.New("BOOTSTRAP_ADMIN_PASSWORD must have at least 12 characters")
	}
	key, err := parseEncryptionKey(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return c, err
	}
	c.EncryptionKey = key
	return c, nil
}

func parseEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("ENCRYPTION_KEY is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("ENCRYPTION_KEY must be 32 raw bytes or base64-encoded 32 bytes")
}
