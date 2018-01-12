package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/twz123/oidc-reverse-proxy/pkg/auth"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type FlowConfig struct {
	IssuerURL              *url.URL
	ClientID, ClientSecret string
	RedirectURL            *url.URL
	Context                context.Context
	HTTPTransport          *http.Transport
}
type flow struct {
	context      context.Context
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	redirectURL  *url.URL
	cookieName   string
}

func NewOpenIDConnectFlow(config *FlowConfig) (auth.Flow, error) {

	context := oidc.ClientContext(config.Context, &http.Client{
		Transport: config.HTTPTransport,
	})

	provider, err := oidc.NewProvider(context, config.IssuerURL.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create OpenID Connect provider %s", config.IssuerURL)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL.String(),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &flow{
		context:      context,
		oidcProvider: provider,
		oidcVerifier: verifier,
		oauth2Config: &oauth2Config,
		redirectURL:  config.RedirectURL,
	}, nil
}

type challenge struct {
	flow        *flow
	state       string
	targetURL   *url.URL
	redirectURL *url.URL
}

func (flow *flow) NewAuthenticator(targetURL *url.URL) (authenticator auth.Authenticator, redirectURL *url.URL, err error) {
	state, err := generateRandomState()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate random state")
	}

	redirectURL, err = url.Parse(flow.oauth2Config.AuthCodeURL(state))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate redirect URI")
	}

	return &challenge{
		flow:        flow,
		state:       state,
		targetURL:   targetURL,
		redirectURL: redirectURL,
	}, redirectURL, nil
}

func (challenge *challenge) Authenticate(request *http.Request) (authentication auth.Authentication, newAuthenticator auth.Authenticator, err error) {
	if challenge == nil {
		return nil, nil, errors.New("no active challenge")
	}

	if request.URL.Path != challenge.flow.redirectURL.Path {
		return nil, nil, errors.Errorf("paths don't match: expected %s, got %s", challenge.flow.redirectURL.Path, request.URL.Path)
	}

	state := request.URL.Query().Get("state")
	if state != challenge.state {
		return nil, nil, errors.Errorf("state didn't match: expected %s, got %s", challenge.state, state)
	}

	oauth2Token, err := challenge.flow.oauth2Config.Exchange(challenge.flow.context, request.URL.Query().Get("code"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to exchange code")
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, nil, errors.Wrap(err, "no ID Token in server response")
	}

	// Parse and verify ID Token payload.
	idToken, err := challenge.flow.oidcVerifier.Verify(challenge.flow.context, rawIDToken)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to verify ID Token")
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse claims")
	}

	if !claims.Verified {
		return nil, nil, errors.Errorf("email has not been verified: %s", claims.Email)
	}

	return &redirectingAuthentication{challenge.targetURL}, &verifiedToken{
		auth.BearerToken{Value: rawIDToken},
		challenge.flow,
		idToken.Expiry,
	}, nil
}

type verifiedToken struct {
	auth.BearerToken
	flow   *flow
	expiry time.Time
}

func (token *verifiedToken) Authenticate(request *http.Request) (auth.Authentication, auth.Authenticator, error) {
	if time.Until(token.expiry) < 30*time.Second {
		newAuthenticator, redirectURL, err := token.flow.NewAuthenticator(request.URL)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to create authenticator to obtain new token")
		}

		return &redirectingAuthentication{redirectURL}, newAuthenticator, nil
	}

	return token, nil, nil
}

type redirectingAuthentication struct {
	redirectURL *url.URL
}

func (r *redirectingAuthentication) InjectInto(request *http.Request) *url.URL {
	return r.redirectURL
}

func generateRandomState() (string, error) {
	bytes := make([]byte, 18)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}
