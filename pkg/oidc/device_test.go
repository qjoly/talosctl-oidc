package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestDeviceCodeAppliesRFCDefaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.FormValue("scope"); got != "openid email" {
			t.Errorf("scope = %q, want %q", got, "openid email")
		}
		w.Header().Set("Content-Type", "application/json")
		// No interval and no expires_in: the client must fill in the defaults.
		w.Write([]byte(`{"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://idp/device"}`))
	}))
	defer srv.Close()

	auth, err := RequestDeviceCode(context.Background(), &ProviderConfig{DeviceAuthorizationEndpoint: srv.URL}, "cid", "", []string{"openid", "email"})
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}
	if auth.Interval != 5 {
		t.Errorf("Interval = %d, want the RFC default of 5", auth.Interval)
	}
	if auth.ExpiresIn != 600 {
		t.Errorf("ExpiresIn = %d, want the default of 600", auth.ExpiresIn)
	}
}

func TestRequestDeviceCodeWithoutEndpoint(t *testing.T) {
	if _, err := RequestDeviceCode(context.Background(), &ProviderConfig{}, "cid", "", nil); err == nil {
		t.Fatal("expected an error when the provider advertises no device endpoint")
	}
}

func TestPollDeviceTokenSucceedsAfterPending(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.FormValue("grant_type"); got != deviceCodeGrantType {
			t.Errorf("grant_type = %q, want %q", got, deviceCodeGrantType)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		w.Write([]byte(`{"access_token":"at","id_token":"it","expires_in":300}`))
	}))
	defer srv.Close()

	auth := &DeviceAuth{DeviceCode: "dc", UserCode: "WDJB-MJHT", Interval: 1, ExpiresIn: 60}
	resp, err := PollDeviceToken(context.Background(), &ProviderConfig{TokenEndpoint: srv.URL}, "cid", "", auth)
	if err != nil {
		t.Fatalf("PollDeviceToken: %v", err)
	}
	if resp.IDToken != "it" {
		t.Errorf("IDToken = %q, want %q", resp.IDToken, "it")
	}
	if calls != 2 {
		t.Errorf("polled %d times, want 2", calls)
	}
}

func TestPollDeviceTokenSurfacesProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"access_denied","error_description":"user refused"}`))
	}))
	defer srv.Close()

	auth := &DeviceAuth{DeviceCode: "dc", Interval: 1, ExpiresIn: 60}
	_, err := PollDeviceToken(context.Background(), &ProviderConfig{TokenEndpoint: srv.URL}, "cid", "", auth)
	if err == nil {
		t.Fatal("expected access_denied to end the polling")
	}
}

func TestPollDeviceTokenStopsWhenCodeExpired(t *testing.T) {
	auth := &DeviceAuth{DeviceCode: "dc", Interval: 1, ExpiresIn: -1}
	_, err := PollDeviceToken(context.Background(), &ProviderConfig{TokenEndpoint: "http://127.0.0.1:1"}, "cid", "", auth)
	if err == nil {
		t.Fatal("expected an expired device code to stop the polling")
	}
}

func TestPollDeviceTokenHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"authorization_pending"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	auth := &DeviceAuth{DeviceCode: "dc", Interval: 1, ExpiresIn: 600}
	if _, err := PollDeviceToken(ctx, &ProviderConfig{TokenEndpoint: srv.URL}, "cid", "", auth); err == nil {
		t.Fatal("expected the poll to stop when the context expires")
	}
}
