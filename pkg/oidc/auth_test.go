package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// freePort grabs a port the OS just handed out, then releases it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestCallbackServerListensOnEveryAddress(t *testing.T) {
	addrs := []string{
		fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	}

	cs, err := NewCallbackServer(addrs)
	if err != nil {
		t.Fatalf("NewCallbackServer: %v", err)
	}
	cs.Start()
	defer cs.Shutdown(context.Background())

	if want := "http://" + addrs[0] + "/callback"; cs.RedirectURI() != want {
		t.Errorf("RedirectURI() = %q, want %q", cs.RedirectURI(), want)
	}

	// The callback must be answered on the second address too, not only the first.
	resp, err := http.Get("http://" + addrs[1] + "/callback?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("calling second listener: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := cs.WaitForCallback(ctx)
	if err != nil {
		t.Fatalf("WaitForCallback: %v", err)
	}
	if result.Code != "abc" || result.State != "xyz" {
		t.Errorf("got code=%q state=%q, want code=abc state=xyz", result.Code, result.State)
	}
}

func TestCallbackServerRejectsEmptyAddressList(t *testing.T) {
	if _, err := NewCallbackServer(nil); err == nil {
		t.Fatal("expected an error with no listen address")
	}
}

func TestCallbackServerReleasesListenersOnBindFailure(t *testing.T) {
	good := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	if _, err := NewCallbackServer([]string{good, "127.0.0.1:not-a-port"}); err == nil {
		t.Fatal("expected a bind error")
	}

	// The first port must be free again, otherwise a retry would fail.
	l, err := net.Listen("tcp", good)
	if err != nil {
		t.Fatalf("port %s left bound after a failed bind: %v", good, err)
	}
	l.Close()
}
