package auth

import (
	"net/http"
	"net/url"
)

// Authentication encapsulates autentication info that can be injected into a HTTP request.
type Authentication interface {
	InjectInto(request *http.Request) (redirectURL *url.URL)
}

type Authenticator interface {
	Authenticate(request *http.Request) (auth Authentication, newAuthenticator Authenticator, err error)
}

type Flow interface {
	NewAuthenticator(targetURL *url.URL) (authenticator Authenticator, redirectURL *url.URL, err error)
}
