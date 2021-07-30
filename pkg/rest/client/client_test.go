package client

import (
	"testing"
)

func TestCreation(t *testing.T) {
	// Here just to test compilation
	client := New(nil)
	if client == nil {
		t.Error("This is impossible")
	}
}
