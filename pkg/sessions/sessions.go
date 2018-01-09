package sessions

import (
	"github.com/twz123/oidc-reverse-proxy/pkg/auth"
)

type Store interface {
	NewSession(auth.Authenticator) (Session, error)
	Get(sessionID string) Session
	EvictInactive()
}

type Session interface {
	ID() string
	DoWith(func(LockedSession))
}

type LockedSession interface {
	Session
	Authenticator() auth.Authenticator
	SetAuthenticator(auth.Authenticator)
}
