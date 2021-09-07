package client

import (
	"context"
	"math/rand"
	"net/url"
	"os"
	"testing"

	"github.com/deviceplane/go-sdk/pkg/client"
)

var (
	testClient *client.Client
	password   string
	email      string
	project    string
	projectID  string
	regToken   string
	devID      string
)

const (
	company   = "Edgeworx"
	firstName = "Test"
	lastName  = "Testovich"
	roleYAML  = `rules:
- resources:
  - '*'
  actions:
  - write`
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
	testClient = client.New(baseURL)
	if testClient == nil {
		t.Fatal("testClient is nil")
	}
}

// TODO: Enable when temp email integrated
// func TestCreateUser(t *testing.T) {
// 	email = fmt.Sprintf("gotest%s@testworx.io", randomString(7))
// 	password = os.Getenv("USER_PW")
// 	if password == "" {
// 		t.Fatal("Environment variable USER_PW is not set")
// 	}
// 	user, err := testClient.CreateUser(context.Background(), &client.UserCreate{
// 		Company:   company,
// 		Email:     email,
// 		FirstName: firstName,
// 		LastName:  lastName,
// 		Password:  password,
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to created user: %s", err.Error())
// 	}
// 	if user == nil {
// 		t.Error("user is nil")
// 	}
// }

func TestLogin(t *testing.T) {
	email = os.Getenv("USER_EMAIL")
	if email == "" {
		t.Fatal("USER_EMAIL is not set")
	}
	password = os.Getenv("USER_PW")
	if password == "" {
		t.Fatal("USER_PW is not set")
	}
	err := testClient.Login(context.Background(), &client.LoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Errorf("Failed to login: %s", err.Error())
	}
}

func TestCreateProject(t *testing.T) {
	project = randomString(30)
	proj, err := testClient.CreateProject(context.Background(), project)
	if err != nil {
		t.Fatalf("Failed to created project: %s", err.Error())
	}
	if proj == nil {
		t.Fatal("proj is nil")
	}
	projectID = proj.ID
}

func TestCreateRBACResources(t *testing.T) {
	// Registration Token
	tokenReq := client.RegistrationToken{
		Name:             randomString(10),
		Description:      "default",
		MaxRegistrations: 10,
	}
	tokenResp, err := testClient.CreateRegistrationToken(context.Background(), projectID, tokenReq)
	if err != nil {
		t.Errorf("Failed to create registration token: %s", err.Error())
		return
	}
	if tokenResp == nil {
		t.Errorf("tokenResp is nil")
		return
	}
	// Service Account
	svcAccReq := client.ServiceAccountCreate{
		Name:        randomString(10),
		Description: "default",
	}
	svcAccResp, err := testClient.CreateServiceAccount(context.Background(), projectID, svcAccReq)
	if err != nil {
		t.Errorf("Failed to create service account: %s", err.Error())
		return
	}
	if svcAccResp == nil {
		t.Errorf("svcAccResp is nil")
		return
	}
	// Role
	roleReq := &client.RoleCreate{
		Name:   randomString(10),
		Config: roleYAML,
	}
	roleResp, err := testClient.CreateRole(context.Background(), projectID, roleReq)
	if err != nil {
		t.Errorf("Failed to create role: %s", err.Error())
		return
	}
	if roleResp == nil {
		t.Errorf("roleResp is nil")
		return
	}
	// Role binding
	roleBindingResp, err := testClient.CreateRoleBinding(context.Background(), projectID, svcAccResp.ID, roleResp.ID)
	if err != nil {
		t.Errorf("Failed to create role binding: %s", err.Error())
		return
	}
	if roleBindingResp == nil {
		t.Error("roleBindingResp is nil")
		return
	}
	// Access Key
	accessKeyResp, err := testClient.CreateAccessKey(context.Background(), projectID, svcAccResp.ID)
	if err != nil {
		t.Errorf("Failed to create access key: %s", err.Error())
		return
	}
	if accessKeyResp == nil {
		t.Error("accessKeyResp is nil")
		return
	}
	regToken = tokenResp.ID
}

func TestRegisterDevice(t *testing.T) {
	regDevResp, err := testClient.RegisterDevice(context.Background(), projectID, regToken)
	if err != nil {
		t.Errorf("Failed to register device: %s", err.Error())
	} else {
		devID = regDevResp.DeviceID
	}
}

func getDevice(t *testing.T) *client.Device {
	getDev, err := testClient.GetDevice(context.Background(), projectID, devID)
	if err != nil {
		t.Errorf("Failed to get device: %s", err.Error())
	}
	if getDev == nil {
		t.Errorf("Device is nil from get device")
		return nil
	}
	if getDev.ID != devID {
		t.Errorf("Expected {%s} device id does not match found {%s}", devID, getDev.ID)
	}
	return getDev
}

func TestGetDevice(t *testing.T) {
	_ = getDevice(t)
}

func TestUpdateDevice(t *testing.T) {
	newName := randomString(20)
	_, err := testClient.UpdateDevice(context.Background(), projectID, devID, client.UpdateDeviceRequest{Name: newName})
	if err != nil {
		t.Errorf("Failed to update device: %s", err.Error())
	}
	getDev := getDevice(t)
	if getDev.Name != newName {
		t.Errorf("Expected {%s} device name does not match found {%s}", newName, getDev.Name)
	}
}
func TestDeleteDevice(t *testing.T) {
	err := testClient.DeleteDevice(context.Background(), projectID, devID)
	if err != nil {
		t.Errorf("Failed to delete device: %s", err.Error())
	}
}

func TestDeleteProject(t *testing.T) {
	err := testClient.DeleteProject(context.Background(), projectID)
	if err != nil {
		t.Errorf("Failed to delete project: %s", err.Error())
	}
}
