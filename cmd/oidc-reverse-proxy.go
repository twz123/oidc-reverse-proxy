package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/twz123/oidc-reverse-proxy/pkg/auth/oidc"
	"github.com/twz123/oidc-reverse-proxy/pkg/handler"
	"github.com/twz123/oidc-reverse-proxy/pkg/sessions"
)

const (
	xOK = iota
	xGeneralError
	xCLIUsage
)

func main() {
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGTERM, os.Interrupt)

	code, msg := run(osSignals)
	switch code {
	case xOK:
		glog.Info("Exiting application")
		return

	case xCLIUsage:
		fmt.Fprintln(os.Stderr, msg)
		flag.Usage()

	case xGeneralError:
		glog.Error(msg)
	}

	os.Exit(code)
}

func run(osSignals <-chan os.Signal) (int, string) {
	bindAddress := flag.String("bind-address", "127.0.0.1:8080", "")
	rawUpstreamURL := flag.String("upstream-url", "", "")
	tlsVerifyUpstream := flag.Bool("tls-verify-upstream", true, "")
	rawIssuerURL := flag.String("issuer-url", "https://accounts.google.com", "")
	tlsVerifyIssuer := flag.Bool("tls-verify-issuer", true, "")
	clientID := flag.String("client-id", "", "")
	clientSecret := flag.String("client-secret", "", "")
	rawRredirectURL := flag.String("redirect-url", "", "")
	rawSessionInactivityThreshold := flag.String("session-inactivity-threshold", "5m", "")
	cookieName := flag.String("cookie-name", "_oidc_authentication", "")
	cookieDomain := flag.String("cookie-domain", "", "")
	cookiePath := flag.String("cookie-path", "", "")
	cookieHTTPOnly := flag.Bool("cookie-http-only", true, "")
	cookieSecure := flag.Bool("cookie-secure", true, "")

	flag.Parse()

	if *bindAddress == "" {
		return xCLIUsage, "-bind-address missing"
	}
	if *rawUpstreamURL == "" {
		return xCLIUsage, "-upstream-url missing"
	}
	upstreamURL, err := url.Parse(*rawUpstreamURL)
	if err != nil {
		return xCLIUsage, fmt.Sprintf("-upstream-url invalid: %s", err)
	}
	if *rawIssuerURL == "" {
		return xCLIUsage, "-issuer-url missing"
	}
	issuerURL, err := url.Parse(*rawIssuerURL)
	if err != nil {
		return xCLIUsage, fmt.Sprintf("-issuer-url invalid: %s", err)
	}
	if *clientID == "" {
		return xCLIUsage, "-client-id missing"
	}
	if *clientSecret == "" {
		return xCLIUsage, "-client-secret missing"
	}
	if *rawRredirectURL == "" {
		return xCLIUsage, "-redirect-url missing"
	}
	redirectURL, err := url.Parse(*rawRredirectURL)
	if err != nil {
		return xCLIUsage, fmt.Sprintf("-redirect-url missing: %s", err)
	}
	sessionInactivityThreshold, err := time.ParseDuration(*rawSessionInactivityThreshold)
	if err != nil {
		return xCLIUsage, fmt.Sprintf("-session-inactivity-threshold invalid: %s", err)
	}
	if *cookieName == "" {
		return xCLIUsage, "-cookie-name missing"
	}
	if *cookieDomain == "" {
		return xCLIUsage, "-cookie-domain missing"
	}
	if *cookiePath == "" {
		return xCLIUsage, "-cookie-path missing"
	}

	glog.Info("Initializing application")

	if !*tlsVerifyUpstream {
		glog.Warning("TLS certificate verification is turned off for upstream URL ", upstreamURL)
	}
	if !*tlsVerifyIssuer {
		glog.Warning("TLS certificate verification is turned off for OpenID Connect Issuer URL ", issuerURL)
	}

	authFlow, err := oidc.NewOpenIDConnectFlow(&oidc.FlowConfig{
		IssuerURL:     issuerURL,
		ClientID:      *clientID,
		ClientSecret:  *clientSecret,
		RedirectURL:   redirectURL,
		Context:       context.Background(),
		HTTPTransport: newHTTPTransport(*tlsVerifyIssuer),
	})
	if err != nil {
		return xGeneralError, err.Error()
	}

	sessions := sessions.NewInMemoryStore(sessionInactivityThreshold)
	httpServer := &http.Server{
		Addr: *bindAddress,
		Handler: handler.NewAuthProxyHandler(
			&handler.Upstream{
				URL:       upstreamURL,
				Transport: newHTTPTransport(*tlsVerifyUpstream),
			},
			authFlow,
			sessions,
			&http.Cookie{
				Name:     *cookieName,
				Domain:   *cookieDomain,
				Path:     *cookiePath,
				HttpOnly: *cookieHTTPOnly,
				Secure:   *cookieSecure,
			}),
	}

	shutdown := make(chan bool, 1)
	var shutdownLatch sync.WaitGroup

	defer func() {
		close(shutdown)
		shutdownLatch.Wait()
	}()

	sessionEvictionTicker := time.NewTicker(1 * time.Minute)
	shutdownLatch.Add(1)
	go func() {
		glog.Info("Starting session evictor")

	sessionEvictor:
		for {
			select {
			case <-sessionEvictionTicker.C:
				glog.Info("Start evicting inactive sessions")
				sessions.EvictInactive()
				glog.Info("Done evicting inactive sessions")
			case <-shutdown:
				break sessionEvictor
			}
		}

		glog.Info("Exiting session evictor")
		shutdownLatch.Done()
	}()

	shutdownLatch.Add(1)
	go func() {
		select {
		case <-osSignals:
			glog.Info("Signal received")
		case <-shutdown:
		}

		glog.Info("Shutting down")
		sessionEvictionTicker.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		httpServer.Shutdown(ctx)
		cancel()
		shutdownLatch.Done()
	}()

	glog.Info("Starting HTTP server")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return xGeneralError, fmt.Sprintf("HTTP server exited: %s", err)
	}

	glog.Info("HTTP server exited normally")

	return xOK, ""
}

func newHTTPTransport(tlsVerify bool) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !tlsVerify,
		},
	}
}
