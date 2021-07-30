package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	meURL           = "me"
	registerURL     = "register"
	loginURL        = "login"
	projectsURL     = "projects"
	devicesURL      = "devices"
	membershipsURL  = "memberships"
	setCookieHeader = "Set-Cookie"
	cookieHeader    = "Cookie"
)

type Client struct {
	url        *url.URL
	accessKey  string
	httpClient *http.Client
	cookie     string
}

func New(endpoint *url.URL) *Client {
	return &Client{
		url:        endpoint,
		accessKey:  "", // TODO: Do we need this ever?
		httpClient: http.DefaultClient,
	}
}

func (c *Client) CreateUser(ctx context.Context, user *UserCreate) (*User, error) {
	var response User
	if err := c.post(ctx, *user, &response, registerURL); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) DeleteUser(ctx context.Context, user *LoginRequest) error {
	if err := c.delete(ctx, user, meURL); err != nil {
		return err
	}
	return nil
}

func (c *Client) Login(ctx context.Context, login *LoginRequest) error {
	if err := c.post(ctx, *login, nil, loginURL); err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteProject(ctx context.Context, projectID string) error {
	delURL := fmt.Sprintf("%s/%s", projectsURL, projectID)
	if err := c.delete(ctx, nil, delURL); err != nil {
		return err
	}
	return nil
}

func (c *Client) CreateProject(ctx context.Context, name string) (*Project, error) {
	var project Project
	if err := c.post(ctx, Project{Name: name}, &project, projectsURL); err != nil {
		return nil, err
	}
	return &project, nil
}

func (c *Client) CreateRegistrationToken(ctx context.Context, projectID string, token RegistrationToken) (*DeviceRegistrationToken, error) {
	var response DeviceRegistrationToken
	if err := c.post(ctx, token, &response, getRegistrationTokensURL(projectID)); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateServiceAccount(ctx context.Context, projectID string, serviceAccount ServiceAccountCreate) (*ServiceAccount, error) {
	var response ServiceAccount
	if err := c.post(ctx, serviceAccount, &response, getServiceAccountsURL(projectID)); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateAccessKey(ctx context.Context, projectID, serviceAccountID string) (*ServiceAccountAccessKeyWithValue, error) {
	var response ServiceAccountAccessKeyWithValue
	if err := c.post(ctx, response, &response, getAccessKeysURL(projectID, serviceAccountID)); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateRole(ctx context.Context, projectID string, role *RoleCreate) (*Role, error) {
	var response Role
	if err := c.post(ctx, *role, &response, getRolesURL(projectID)); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateRoleBinding(ctx context.Context, projectID, serviceAccountID, roleID string) (*ServiceAccountRoleBinding, error) {
	var response ServiceAccountRoleBinding
	if err := c.post(ctx, response, &response, getBindingURL(projectID, serviceAccountID, roleID)); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ListProjects(ctx context.Context, project string) ([]ProjectFull, error) {
	var memberships []MembershipFull1
	if err := c.get(ctx, &memberships, membershipsURL+"?full"); err != nil {
		return nil, err
	}

	projects := make([]ProjectFull, len(memberships))
	for idx := range memberships {
		projects[idx] = memberships[idx].Project
	}
	return projects, nil
}

func (c *Client) ListDevices(ctx context.Context, filters []Filter, project string) ([]Device, error) {
	var devices []Device

	urlValues := url.Values{}
	for _, filter := range filters {
		jsonData, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}

		b64Filter := base64.StdEncoding.EncodeToString(jsonData)
		urlValues.Add("filter", b64Filter)
	}

	var queryString string
	if encoded := urlValues.Encode(); encoded != "" {
		queryString = "?" + encoded
	}

	if err := c.get(ctx, &devices, projectsURL, project, devicesURL+queryString); err != nil {
		return nil, err
	}
	return devices, nil
}

func (c *Client) GetDevice(ctx context.Context, project, device string) (*Device, error) {
	var d Device
	if err := c.get(ctx, &d, projectsURL, project, devicesURL, device+"?full"); err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) RegisterDevice(ctx context.Context, projectID, registrationTokenID string) (*RegisterDeviceResponse, error) {
	req := RegisterDeviceRequest{
		DeviceRegistrationTokenID: registrationTokenID,
	}

	var registerDeviceResponse RegisterDeviceResponse
	err := c.post(ctx, req, &registerDeviceResponse, "projects", projectID, "devices", "register")
	if err != nil {
		return nil, err
	}

	return &registerDeviceResponse, nil
}

func (c *Client) get(ctx context.Context, out interface{}, s ...string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", getURL(c.url, s...), nil)
	if err != nil {
		return err
	}

	return c.performRequest(req, out)
}

func (c *Client) delete(ctx context.Context, in interface{}, s ...string) error {
	reqBytes := []byte{}
	if in != nil {
		switch v := in.(type) {
		case string:
			reqBytes = []byte(v)
		default:
			var err error
			reqBytes, err = json.Marshal(in)
			if err != nil {
				return err
			}
		}
	}
	reader := bytes.NewReader(reqBytes)
	req, err := http.NewRequestWithContext(ctx, "DELETE", getURL(c.url, s...), reader)
	if err != nil {
		return err
	}

	return c.performRequest(req, nil)
}

func (c *Client) post(ctx context.Context, in, out interface{}, s ...string) error {
	var reqBytes []byte

	switch v := in.(type) {
	case string:
		reqBytes = []byte(v)
	default:
		var err error
		reqBytes, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	reader := bytes.NewReader(reqBytes)

	req, err := http.NewRequestWithContext(ctx, "POST", getURL(c.url, s...), reader)
	if err != nil {
		return err
	}

	return c.performRequest(req, out)
}

func (c *Client) performRequest(req *http.Request, out interface{}) error {
	req.SetBasicAuth(c.accessKey, "")
	req.Header.Add("Referer", req.URL.String())
	if c.cookie != "" {
		req.Header.Add(cookieHeader, c.cookie)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	return c.handleResponse(resp, out)
}

func (c *Client) handleResponse(resp *http.Response, out interface{}) error {
	defer func() {
		resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	strBody := string(body)

	switch resp.StatusCode {
	case http.StatusOK:
		if resp.Header.Get(setCookieHeader) != "" {
			setCookie := resp.Header.Get(setCookieHeader)
			c.cookie = strings.Split(setCookie, ";")[0]
		}
		if out == nil {
			return nil
		}
		if o, ok := out.(*string); ok {
			*o = string(body)
			return nil
		}
		return json.NewDecoder(bytes.NewReader(body)).Decode(&out)
	case http.StatusNotFound:
		return NewNotFoundError(strBody)
	case http.StatusConflict:
		return NewAlreadyExistsError(strBody)
	case http.StatusBadRequest:
		// data, _ := ioutil.ReadAll(resp.Body)
		// TODO: Fix the server
		msgs := []string{
			"email already taken",
			"project name already in use",
			"role name already in use",
		}
		for _, msg := range msgs {
			if strings.Contains(strBody, msg) {
				return NewAlreadyExistsError(strBody)
			}
		}
		return errors.New(strBody)
	default:
		return fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
	}
}

func getURL(u *url.URL, s ...string) string {
	return strings.Join(append([]string{u.String()}, s...), "/")
}

func getRegistrationTokensURL(projectID string) string {
	return fmt.Sprintf("%s/%s/deviceregistrationtokens", projectsURL, projectID)
}

func getServiceAccountsURL(projectID string) string {
	return fmt.Sprintf("%s/%s/serviceaccounts", projectsURL, projectID)
}

func getAccessKeysURL(project, serviceAccount string) string {
	return fmt.Sprintf("%s/%s/serviceaccountaccesskeys", getServiceAccountsURL(project), serviceAccount)
}

func getRolesURL(projectID string) string {
	return fmt.Sprintf("%s/%s/roles", projectsURL, projectID)
}

func getBindingURL(projectID, serviceAccountID, roleID string) string {
	svcAccURL := getServiceAccountsURL(projectID)
	return fmt.Sprintf("%s/%s/roles/%s/serviceaccountrolebindings", svcAccURL, serviceAccountID, roleID)
}
