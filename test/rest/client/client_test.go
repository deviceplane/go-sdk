package client

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"testing"

	"github.com/deviceplane/go-sdk/pkg/rest/client"
)

var (
	testClient *client.Client
	password   string
	email      string
)

const (
	company   = "Edgeworx"
	firstName = "Test"
	lastName  = "Testovich"
	project   = "testproject"
)

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func TestNew(t *testing.T) {
	// Initialize the client
	cloudURL := os.Getenv("CLOUD_URL")
	if cloudURL == "" {
		t.Fatal("Environment variable CLOUD_URL is not set")
	}
	baseURL, err := url.Parse(cloudURL)
	if err != nil {
		t.Fatalf("Failed to parse CLOUD_URL: %s", err.Error())
	}
	testClient := client.New(baseURL)
	if testClient == nil {
		t.Fatal("testClient is nil")
	}
}

func TestCreateUser(t *testing.T) {
	email = fmt.Sprintf("gotest%s@testworx.io", randomString(7))
	password = os.Getenv("USER_PW")
	if password == "" {
		t.Fatal("Environment variable USER_PW is not set")
	}
	user, err := testClient.CreateUser(context.Background(), &client.UserCreate{
		Company:   company,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Password:  password,
	})
	if err != nil {
		t.Fatalf("Failed to created user: %s", err.Error())
	}
	if user == nil {
		t.Error("user is nil")
	}
}

func TestLogin(t *testing.T) {
	err := testClient.Login(context.Background(), &client.LoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Errorf("Failed to login: %s", err.Error())
	}
}

func TestCreateProject(t *testing.T) {
	proj, err := testClient.CreateProject(context.Background(), project)
	if err != nil {
		t.Errorf("Failed to created project: %s", err.Error())
	}
	if proj == nil {
		t.Error("proj is nil")
	}
}
