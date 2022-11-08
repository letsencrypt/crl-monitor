package cmd

import (
	"log"
	"os"
)

// EnvVar is a typed wrapper with helper wrappers around os.LookupEnv
type EnvVar string

// MustRead reads an environment variable.
// If the variable is unset, it logs a message at Fatal level, thus exiting the program.
func (ev EnvVar) MustRead(helpText string) string {
	value, ok := os.LookupEnv(string(ev))
	if !ok {
		log.Fatalf("Environment variable '%s' is unset: %s", ev, helpText)
	}
	return value
}

// LookupEnv is a wrapper for os.LookupEnv
func (ev EnvVar) LookupEnv() (string, bool) {
	return os.LookupEnv(string(ev))
}
