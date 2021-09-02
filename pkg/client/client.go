package client

import (
	"net/http"
	"net/url"
)

type Client struct {
	url        *url.URL
	accessKey  string
	httpClient *http.Client
	cookie     string
	privsToken string
}

func New(endpoint *url.URL) *Client {
	return &Client{
		url:        endpoint,
		httpClient: http.DefaultClient,
	}
}

// SetAccessKey is only required for SSH functionality
func (c *Client) SetAccessKey(accessKey string) {
	c.accessKey = accessKey
}
