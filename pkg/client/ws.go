package client

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/function61/holepunch-server/pkg/wsconnadapter"
	"github.com/gorilla/websocket"
)

const (
	sshURL = "ssh"
)

// SSH provices a connection for a long-lived SSH connection to the device
// via websockets. The returned connection must be closed be the caller
func (c *Client) SSH(ctx context.Context, project, deviceID string) (net.Conn, error) {
	req, err := http.NewRequestWithContext(ctx, "", "", nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.accessKey, "")

	// Caller must close
	wsConn, _, err := websocket.DefaultDialer.Dial(getWebsocketURL(c.url, projectsURL, project, devicesURL, deviceID, sshURL), req.Header) // nolint:bodyclose
	if err != nil {
		return nil, err
	}

	return wsconnadapter.New(wsConn), nil
}

func getWebsocketURL(u *url.URL, s ...string) string {
	uCopy, _ := url.Parse(u.String())
	switch uCopy.Scheme {
	case "http":
		uCopy.Scheme = "ws"
	default:
		uCopy.Scheme = "wss"
	}
	return strings.Join(append([]string{uCopy.String()}, s...), "/")
}
