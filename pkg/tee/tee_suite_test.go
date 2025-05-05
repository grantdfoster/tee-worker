package tee

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTee(t *testing.T) {
	// Skip all TEE tests in CI environment
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping TEE tests in CI environment")
		return
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "TEE Suite")
}
