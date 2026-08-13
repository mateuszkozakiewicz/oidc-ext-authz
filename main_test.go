package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
)

func withConfig(t *testing.T, c Config, fn func()) {
	t.Helper()
	old := cfg
	cfg = c
	defer func() { cfg = old }()
	fn()
}

func testConfig() Config {
	return Config{
		Server: ServerConfig{
			Host:               "auth.example.com",
			DefaultRedirectURL: "https://default.example.com/",
			CallbackPath:       "/oauth2/callback",
			SignOutPath:        "/signout",
		},
		Cookie: CookieConfig{
			Name:   "session",
			Domain: ".example.com",
			Secret: "test-secret",
		},
		Session: SessionConfig{TTL: "1h"},
		Access: map[string][]string{
			"app.example.com": {"alice@example.com"},
		},
	}
}

func TestSignIsDeterministic(t *testing.T) {
	withConfig(t, testConfig(), func() {
		a := sign("payload")
		b := sign("payload")
		if a != b {
			t.Fatalf("expected sign to be deterministic, got %q and %q", a, b)
		}
		if sign("other") == a {
			t.Fatalf("expected different input to produce different signature")
		}
	})
}

func TestSetSessionAndGetSessionRoundTrip(t *testing.T) {
	withConfig(t, testConfig(), func() {
		rec := httptest.NewRecorder()
		if err := setSession(rec, "alice@example.com"); err != nil {
			t.Fatalf("setSession failed: %v", err)
		}

		result := rec.Result()
		if len(result.Cookies()) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(result.Cookies()))
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(result.Cookies()[0])

		session, err := getSession(req)
		if err != nil {
			t.Fatalf("getSession failed: %v", err)
		}
		if session.Email != "alice@example.com" {
			t.Fatalf("expected email alice@example.com, got %s", session.Email)
		}
	})
}

func TestParseJWTRejectsTamperedToken(t *testing.T) {
	withConfig(t, testConfig(), func() {
		rec := httptest.NewRecorder()
		if err := setSession(rec, "alice@example.com"); err != nil {
			t.Fatalf("setSession failed: %v", err)
		}
		cookie := rec.Result().Cookies()[0]

		if _, err := parseJWT(cookie.Value + "tampered"); err == nil {
			t.Fatalf("expected error for tampered token")
		}
	})
}

func TestParseJWTRejectsExpiredToken(t *testing.T) {
	c := testConfig()
	c.Session.TTL = "-1h" // already expired
	withConfig(t, c, func() {
		rec := httptest.NewRecorder()
		if err := setSession(rec, "alice@example.com"); err != nil {
			t.Fatalf("setSession failed: %v", err)
		}
		cookie := rec.Result().Cookies()[0]

		if _, err := parseJWT(cookie.Value); err == nil {
			t.Fatalf("expected error for expired token")
		}
	})
}

func TestParseJWTRejectsMalformedToken(t *testing.T) {
	withConfig(t, testConfig(), func() {
		if _, err := parseJWT("not-a-jwt"); err == nil {
			t.Fatalf("expected error for malformed token")
		}
	})
}

func TestHasAccess(t *testing.T) {
	c := testConfig()
	withConfig(t, c, func() {
		cases := []struct {
			email string
			host  string
			want  bool
		}{
			{"alice@example.com", "app.example.com", true},
			{"ALICE@EXAMPLE.COM", "app.example.com", true}, // case-insensitive
			{"bob@example.com", "app.example.com", false},
			{"alice@example.com", "unknown.example.com", false},
		}
		for _, tc := range cases {
			if got := hasAccess(tc.email, tc.host); got != tc.want {
				t.Errorf("hasAccess(%q, %q) = %v, want %v", tc.email, tc.host, got, tc.want)
			}
		}
	})
}

func sessionCookie(t *testing.T, email string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := setSession(rec, email); err != nil {
		t.Fatalf("setSession failed: %v", err)
	}
	return rec.Result().Cookies()[0]
}

func TestHandleAuthNoSessionRedirectsToGoogle(t *testing.T) {
	withConfig(t, testConfig(), func() {
		oauth2Cfg = &oauth2.Config{ClientID: "test-client-id"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "app.example.com")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Uri", "/dashboard")
		rec := httptest.NewRecorder()

		handleAuth(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if loc == "" {
			t.Fatalf("expected Location header to be set")
		}
	})
}

func TestHandleAuthAuthenticatedOnAuthHostRedirectsToDefault(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", cfg.Server.Host)
		req.AddCookie(sessionCookie(t, "alice@example.com"))
		rec := httptest.NewRecorder()

		handleAuth(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Server.DefaultRedirectURL {
			t.Fatalf("expected redirect to %s, got %s", cfg.Server.DefaultRedirectURL, got)
		}
	})
}

func TestHandleAuthAllowedUserGetsOK(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "app.example.com")
		req.AddCookie(sessionCookie(t, "alice@example.com"))
		rec := httptest.NewRecorder()

		handleAuth(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if got := rec.Header().Get("X-Forwarded-User"); got != "alice@example.com" {
			t.Fatalf("expected X-Forwarded-User header, got %q", got)
		}
	})
}

func TestHandleAuthDeniedUserGetsForbidden(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "app.example.com")
		req.AddCookie(sessionCookie(t, "bob@example.com"))
		rec := httptest.NewRecorder()

		handleAuth(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})
}

func TestGRPCCheckNoSessionRedirects(t *testing.T) {
	withConfig(t, testConfig(), func() {
		oauth2Cfg = &oauth2.Config{ClientID: "test-client-id"}
		srv := &grpcAuthServer{}
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Host:    "app.example.com",
						Path:    "/dashboard",
						Headers: map[string]string{},
					},
				},
			},
		}

		resp, err := srv.Check(nil, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
			t.Fatalf("expected PermissionDenied, got %v", resp.GetStatus().GetCode())
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatalf("expected denied response")
		}
	})
}

func TestGRPCCheckAllowedUser(t *testing.T) {
	withConfig(t, testConfig(), func() {
		cookie := sessionCookie(t, "alice@example.com")
		srv := &grpcAuthServer{}
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Host: "app.example.com:443",
						Path: "/dashboard",
						Headers: map[string]string{
							"cookie": cookie.Name + "=" + cookie.Value,
						},
					},
				},
			},
		}

		resp, err := srv.Check(nil, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if resp.GetStatus().GetCode() != int32(codes.OK) {
			t.Fatalf("expected OK, got %v", resp.GetStatus().GetCode())
		}
		ok := resp.GetOkResponse()
		if ok == nil {
			t.Fatalf("expected ok response")
		}
		if !headerHasValue(ok.GetHeaders(), "X-Forwarded-User", "alice@example.com") {
			t.Fatalf("expected X-Forwarded-User header with alice@example.com")
		}
	})
}

func TestGRPCCheckDeniedUser(t *testing.T) {
	withConfig(t, testConfig(), func() {
		cookie := sessionCookie(t, "bob@example.com")
		srv := &grpcAuthServer{}
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Host: "app.example.com",
						Path: "/dashboard",
						Headers: map[string]string{
							"cookie": cookie.Name + "=" + cookie.Value,
						},
					},
				},
			},
		}

		resp, err := srv.Check(nil, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
			t.Fatalf("expected PermissionDenied, got %v", resp.GetStatus().GetCode())
		}
	})
}

func headerHasValue(headers []*corev3.HeaderValueOption, key, value string) bool {
	for _, h := range headers {
		if h.GetHeader().GetKey() == key && h.GetHeader().GetValue() == value {
			return true
		}
	}
	return false
}

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleMeUnauthorized(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rec := httptest.NewRecorder()

		handleMe(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}

func TestHandleMeAuthenticated(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.AddCookie(sessionCookie(t, "alice@example.com"))
		rec := httptest.NewRecorder()

		handleMe(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

func TestHandleSignOutClearsCookieAndRedirects(t *testing.T) {
	withConfig(t, testConfig(), func() {
		req := httptest.NewRequest(http.MethodGet, "/signout", nil)
		rec := httptest.NewRecorder()

		handleSignOut(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Server.DefaultRedirectURL {
			t.Fatalf("expected redirect to %s, got %s", cfg.Server.DefaultRedirectURL, got)
		}

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
			t.Fatalf("expected cookie to be cleared, got %+v", cookies)
		}
	})
}

func TestLoadConfigAppliesDefaultsAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := `
google:
  clientID: id
  clientSecret: secret
cookie:
  domain: .example.com
server:
  host: auth.example.com
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	old := cfg
	defer func() { cfg = old }()

	if err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Server.Address != ":4181" {
		t.Errorf("expected default address :4181, got %s", cfg.Server.Address)
	}
	if cfg.Server.GRPCAddress != ":4182" {
		t.Errorf("expected default grpcAddress :4182, got %s", cfg.Server.GRPCAddress)
	}
	if cfg.Server.CallbackPath != "/oauth2/callback" {
		t.Errorf("expected default callbackPath, got %s", cfg.Server.CallbackPath)
	}
	if cfg.Cookie.Name != "ext-authz-session" {
		t.Errorf("expected default cookie name, got %s", cfg.Cookie.Name)
	}
	if cfg.Cookie.Secret == "" {
		t.Errorf("expected a generated cookie secret")
	}
	if cfg.Session.TTL != "1h" {
		t.Errorf("expected default session ttl 1h, got %s", cfg.Session.TTL)
	}
}

func TestLoadConfigMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  host: auth.example.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	old := cfg
	defer func() { cfg = old }()

	if err := loadConfig(path); err == nil {
		t.Fatalf("expected error for missing google credentials")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()

	if err := loadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatalf("expected error for missing config file")
	}
}
