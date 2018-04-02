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
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type FlowConfig struct {
	IssuerURL              *url.URL
	ClientID, ClientSecret string
	RedirectURL            *url.URL
	AcceptUnverifiedEmails bool
	Context                context.Context
	HTTPTransport          *http.Transport
	ExtraScopes            []string
}
type flow struct {
	context                context.Context
	oidcProvider           *oidc.Provider
	oidcVerifier           *oidc.IDTokenVerifier
	oauth2Config           *oauth2.Config
	redirectURL            *url.URL
	acceptUnverifiedEmails bool
}

func NewOpenIDConnectFlow(config *FlowConfig) (auth.Flow, error) {

	context := oidc.ClientContext(config.Context, &http.Client{
		Transport: config.HTTPTransport,
	})

	provider, err := oidc.NewProvider(context, config.IssuerURL.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create OpenID Connect provider %s", config.IssuerURL)
	}

	// "openid" is a required scope for OpenID Connect flows.
	scopes := []string{oidc.ScopeOpenID}

	if config.ExtraScopes != nil {
		scopes = append(scopes, config.ExtraScopes...)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL.String(),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		Scopes: scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &flow{
		context:                context,
		oidcProvider:           provider,
		oidcVerifier:           verifier,
		oauth2Config:           &oauth2Config,
		redirectURL:            config.RedirectURL,
		acceptUnverifiedEmails: config.AcceptUnverifiedEmails,
	}, nil
}

type challenge struct {
	flow  *flow
	state string
}

// Used to store the effective target URL of an OIDC dance.
const targetURLQueryParam = "target"

func (flow *flow) NewAuthenticator(targetURL *url.URL) (authenticator auth.Authenticator, redirectURL *url.URL, err error) {
	state, err := generateRandomState()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate random state")
	}

	redirectURL, err = url.Parse(flow.oauth2Config.AuthCodeURL(state))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate redirect URL")
	}

	redirectURLWithTarget, err := flow.redirectURLWithTarget(targetURL, state)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain redirect URL with target")
	}

	return &challenge{
		flow:  flow,
		state: state,
	}, redirectURLWithTarget, nil
}

func (flow *flow) redirectURLWithTarget(targetURL *url.URL, state string) (*url.URL, error) {
	oauth2ConfigForTarget, err := flow.oauth2ConfigForTarget(targetURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain OAuth2 configuration for target URL")
	}

	return url.Parse(oauth2ConfigForTarget.AuthCodeURL(state))
}

func (flow *flow) oauth2ConfigForTarget(targetURL *url.URL) (*oauth2.Config, error) {
	var patchedConfig oauth2.Config

	patchedConfig = *flow.oauth2Config
	patchedRedirectURL, err := url.Parse(patchedConfig.RedirectURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse redirect URL")
	}
	setQueryParam(patchedRedirectURL, targetURLQueryParam, targetURL.String())
	patchedConfig.RedirectURL = patchedRedirectURL.String()

	return &patchedConfig, nil
}

func (c *challenge) Authenticate(request *http.Request) (authentication auth.Authentication, newAuthenticator auth.Authenticator, err error) {
	if c == nil {
		return nil, nil, errors.New("no active challenge")
	}

	if request.URL.Path != c.flow.redirectURL.Path {
		redirectURL, err := c.flow.redirectURLWithTarget(request.URL, c.state)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to obtain redirect URL with target")
		}
		glog.Infof("%s %s >>> not a callback, retrying (%s)", request.RemoteAddr, request.RequestURI, redirectURL)
		return &redirectingAuthentication{redirectURL}, c, nil
	}

	// verify state param
	state := request.URL.Query().Get("state")
	if state != c.state {
		return nil, nil, errors.Errorf("state didn't match: expected %s, got %s", c.state, state)
	}

	// extraxt target URL from callback query param
	targetURL, err := url.Parse(request.URL.Query().Get(targetURLQueryParam))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse target URL")
	}

	// get a configuration that is seeded with the right target URL
	oauth2ConfigForTarget, err := c.flow.oauth2ConfigForTarget(targetURL)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain OAuth2 configuration for target URL")
	}

	// exchange code against the OAuth2 token with the Identity Provider
	glog.Infof("%s %s >>> exchanging code for target URL %s", request.RemoteAddr, request.RequestURI, targetURL)
	oauth2Token, err := oauth2ConfigForTarget.Exchange(c.flow.context, request.URL.Query().Get("code"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to exchange code")
	}

	// extract the ID Token from OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, nil, errors.Wrap(err, "no ID Token in server response")
	}

	// parse and verify ID Token payload
	idToken, err := c.flow.oidcVerifier.Verify(c.flow.context, rawIDToken)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to verify ID Token")
	}

	// extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse claims")
	}

	// enforce a validated email, if required
	if !c.flow.acceptUnverifiedEmails && !claims.Verified {
		return nil, nil, errors.Errorf("email has not been verified: %s", claims.Email)
	}

	// done: return a redirect to the target and the ID token
	return &redirectingAuthentication{targetURL}, &verifiedToken{
		auth.BearerToken{Value: rawIDToken},
		c.flow,
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

func setQueryParam(u *url.URL, key, value string) {
	queryParams := u.Query()
	queryParams.Set(key, value)
	u.RawQuery = queryParams.Encode()
}
