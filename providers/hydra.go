package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

type HydraProvider struct {
	*ProviderData

	HydraClient hydra.SDK
	Verifier    *oidc.IDTokenVerifier
}

func NewHydraProvider(p *ProviderData) *HydraProvider {
	p.ProviderName = "Hydra"
	return &HydraProvider{ProviderData: p}
}

func (p *HydraProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Subject  string `json:"sub"`
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}

	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	s = &SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresOn:    token.Expiry,
		Email:        claims.Email,
		User:         claims.Subject,
	}

	return
}

func (p *HydraProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn
	s.ExpiresOn = time.Now().Add(time.Second).Truncate(time.Second)
	fmt.Printf("refreshed access token %s (expired on %s)\n", s, origExpiration)
	return false, nil
}

func (p *HydraProvider) CheckPermission(token string) (bool, error) {
	req := swagger.WardenTokenAccessRequest{
		Action:   "view",
		Resource: p.ProtectedResource,
		Scopes:   strings.Split(p.Scope, " "),
		Token:    token,
	}

	resp, _, err := p.HydraClient.DoesWardenAllowTokenAccessRequest(req)
	if err != nil {
		return false, fmt.Errorf("hydra warden api error: %v", err)
	}

	return resp.Allowed, nil
}
