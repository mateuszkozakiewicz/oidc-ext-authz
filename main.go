package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

// See config example at examples/config.yaml
type Config struct {
	Server  ServerConfig        `yaml:"server"`
	Google  GoogleConfig        `yaml:"google"`
	Cookie  CookieConfig        `yaml:"cookie"`
	Session SessionConfig       `yaml:"session"`
	Access  map[string][]string `yaml:"access"`
}

type ServerConfig struct {
	// Address to listen on, e.g. ":4181"
	Address string `yaml:"address"`
	// Host name of the auth service eg. "auth.example.com"
	Host string `yaml:"host"`
	// CallbackPath e.g. "/oauth2/callback"
	CallbackPath string `yaml:"callbackPath"`
	// SignOutPath e.g. "/signout"
	SignOutPath string `yaml:"signOutPath"`
	// DefaultRedirectURL redirect URL when no original URL is available
	DefaultRedirectURL string `yaml:"defaultRedirectURL"`
}

type GoogleConfig struct {
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
}

type CookieConfig struct {
	// Cookie name, e.g. "ext-authz-session"
	Name string `yaml:"name"`
	// Domain scopes for the cookie, e.g. ".example.com"
	Domain string `yaml:"domain"`
	// Secret to sign the cookie
	Secret string `yaml:"secret"`
	// Secure flag on the cookie
	Secure bool `yaml:"secure"`
}

type SessionConfig struct {
	// TTL controls how long a session is valid, e.g. "168h" for 1 week
	TTL string `yaml:"ttl"`
}

type SessionClaims struct {
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

var (
	cfg       Config
	oauth2Cfg *oauth2.Config
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/config/config.yaml"
	}

	if err := loadConfig(configPath); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	oauth2Cfg = &oauth2.Config{
		ClientID:     cfg.Google.ClientID,
		ClientSecret: cfg.Google.ClientSecret,
		RedirectURL:  fmt.Sprintf("https://%s%s", cfg.Server.Host, cfg.Server.CallbackPath),
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Server.CallbackPath, handleCallback)
	mux.HandleFunc(cfg.Server.SignOutPath, handleSignOut)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/me", handleMe)
	mux.HandleFunc("/", handleAuth)

	addr := cfg.Server.Address
	if addr == "" {
		addr = ":4181"
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("shutdown complete")
}

// forward auth endpoint called by reverse proxy
func handleAuth(w http.ResponseWriter, r *http.Request) {
	// extract original request details from forwarded headers
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	originalURL := fmt.Sprintf("%s://%s%s", proto, host, uri)

	// validate session cookie
	session, err := getSession(r)
	if err != nil || session == nil {
		// no valid session — initiate Google OAuth flow
		state := base64.URLEncoding.EncodeToString([]byte(originalURL))
		authURL := oauth2Cfg.AuthCodeURL(
			state,
		)
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// user is authenticated but accessing the auth service host itself — redirect to default URL
	if host == cfg.Server.Host {
		http.Redirect(w, r, cfg.Server.DefaultRedirectURL, http.StatusFound)
		return
	}

	// check if email is allowed for this host
	if !hasAccess(session.Email, host) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// allowed — forward user info to backend via headers
	w.Header().Set("X-Forwarded-User", session.Email)
	w.Header().Set("X-Auth-Request-Email", session.Email)
	w.WriteHeader(http.StatusOK)
}

// processes Google's OAuth2 callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := oauth2Cfg.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	email, err := extractEmail(token)
	if err != nil {
		log.Printf("failed to extract email: %v", err)
		http.Error(w, "failed to get user info", http.StatusUnauthorized)
		return
	}

	originalURLBytes, err := base64.URLEncoding.DecodeString(state)
	originalURL := cfg.Server.DefaultRedirectURL
	if err == nil && len(originalURLBytes) > 0 {
		originalURL = string(originalURLBytes)
	}

	// set signed session cookie
	if err := setSession(w, email); err != nil {
		log.Printf("failed to set session: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	log.Printf("authenticated user %s, redirecting to %s", email, originalURL)
	http.Redirect(w, r, originalURL, http.StatusFound)
}

// clears the session cookie
func handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    cfg.Cookie.Name,
		Value:   "",
		Domain:  cfg.Cookie.Domain,
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
		Secure:  cfg.Cookie.Secure,
	})

	redirect := r.URL.Query().Get("rd")
	if redirect == "" {
		redirect = cfg.Server.DefaultRedirectURL
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// returns 200 OK
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// checks if an email is allowed to access a given host
func hasAccess(email, host string) bool {
	allowed, ok := cfg.Access[host]
	if !ok {
		return false
	}
	for _, e := range allowed {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

// returns the authenticated user's claims or 401 if not authenticated
func handleMe(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// creates and sets a signed session cookie
func setSession(w http.ResponseWriter, email string) error {
	ttl, err := time.ParseDuration(cfg.Session.TTL)
	if err != nil {
		return err
	}

	claims := SessionClaims{
		Email: email,
		Exp:   time.Now().Add(ttl).Unix(),
	}

	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(data)
	signingInput := header + "." + payload
	signature := sign(signingInput)
	value := signingInput + "." + signature

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    value,
		Domain:   cfg.Cookie.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
	return nil
}

// reads and validates the session cookie
func getSession(r *http.Request) (*SessionClaims, error) {
	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(cookie.Value, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 segments")
	}

	signingInput := parts[0] + "." + parts[1]
	if sign(signingInput) != parts[2] {
		return nil, fmt.Errorf("invalid JWT signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims SessionClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse session: %w", err)
	}

	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("session expired")
	}

	return &claims, nil
}

// creates an HMAC-SHA256 signature for the given data
func sign(data string) string {
	h := hmac.New(sha256.New, []byte(cfg.Cookie.Secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// pulls the email claim from the Google ID token
func extractEmail(token *oauth2.Token) (string, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in response")
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid id_token format")
	}

	// add padding if needed
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// try raw encoding
		data, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode id_token payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("email claim not found in id_token")
	}

	return email, nil
}

// reads and parses the YAML config file
func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// validate required fields
	if cfg.Google.ClientID == "" {
		return fmt.Errorf("google.clientID is required")
	}
	if cfg.Google.ClientSecret == "" {
		return fmt.Errorf("google.clientSecret is required")
	}
	if cfg.Cookie.Domain == "" {
		return fmt.Errorf("cookie.domain is required")
	}
	if cfg.Server.Host == "" {
		return fmt.Errorf("server.host is required")
	}

	// set defaults
	if cfg.Server.Address == "" {
		log.Printf("server.address not set, defaulting to :4181")
		cfg.Server.Address = ":4181"
	}
	if cfg.Server.DefaultRedirectURL == "" {
		log.Printf("server.defaultRedirectURL not set, defaulting to https://%s/me", cfg.Server.Host)
		cfg.Server.DefaultRedirectURL = fmt.Sprintf("https://%s/me", cfg.Server.Host)
	}
	if cfg.Server.CallbackPath == "" {
		log.Printf("server.callbackPath not set, defaulting to /oauth2/callback")
		cfg.Server.CallbackPath = "/oauth2/callback"
	}
	if cfg.Server.SignOutPath == "" {
		log.Printf("server.signOutPath not set, defaulting to /signout")
		cfg.Server.SignOutPath = "/signout"
	}
	if cfg.Cookie.Secret == "" {
		// generate a random secret if not provided
		log.Printf("cookie.secret not set, generating a random secret")
		cfg.Cookie.Secret = base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	if cfg.Cookie.Name == "" {
		log.Printf("cookie.name not set, defaulting to ext-authz-session")
		cfg.Cookie.Name = "ext-authz-session"
	}
	if cfg.Session.TTL == "" {
		log.Printf("session.ttl not set, defaulting to 1h (1 hour)")
		cfg.Session.TTL = "1h"
	}

	return nil
}
