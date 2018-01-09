package sessions

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/golang/glog"

	"github.com/pkg/errors"
	"github.com/twz123/oidc-reverse-proxy/pkg/auth"
)

func NewInMemoryStore(inactivityThreshold time.Duration) Store {
	return &memStore{
		sessions:            make(map[string]*memSession),
		inactivityThreshold: inactivityThreshold,
	}
}

type memSession struct {
	lock          sync.Mutex
	id            string
	authenticator auth.Authenticator
	lastSeen      time.Time
}

type lockedMemSession struct {
	session *memSession
}

type memStore struct {
	lock                sync.RWMutex
	sessions            map[string]*memSession
	inactivityThreshold time.Duration
}

func (store *memStore) NewSession(authenticator auth.Authenticator) (Session, error) {
	if authenticator == nil {
		return nil, errors.New("a newly created session needs an authenticator")
	}
	sessionID, err := generateRandomSessionID()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random session ID")
	}

	session := &memSession{
		id:            sessionID,
		authenticator: authenticator,
		lastSeen:      time.Now(),
	}

	store.lock.Lock()
	store.sessions[sessionID] = session
	store.lock.Unlock()

	return session, nil
}

func (store *memStore) Get(sessionID string) Session {
	now := time.Now()

	store.lock.RLock()
	session, exists := store.sessions[sessionID]
	store.lock.RUnlock()

	if !exists || session == nil {
		return nil
	}

	session.lock.Lock()
	inactivityDuration := now.Sub(session.lastSeen)
	shouldEvict := inactivityDuration >= store.inactivityThreshold
	if !shouldEvict {
		session.lastSeen = now
	}
	session.lock.Unlock()

	if shouldEvict {
		go func() {
			store.lock.RLock()
			glog.Infof("Evicting session %s which was inactive for %dns", sessionID, inactivityDuration)
			delete(store.sessions, sessionID)
			store.lock.RUnlock()
		}()

		return nil
	}

	return session
}

func (store *memStore) EvictInactive() {
	store.lock.Lock()
	defer store.lock.Unlock()

	now := time.Now()
	for sessionID, session := range store.sessions {
		session.lock.Lock()
		lastSeen := session.lastSeen
		session.lock.Unlock()
		inactivityDuration := now.Sub(lastSeen)
		if now.Sub(lastSeen) >= store.inactivityThreshold {
			glog.Infof("Evicting session %s which was inactive for %dns", sessionID, inactivityDuration)
			delete(store.sessions, sessionID)
		}
	}
}

func (session *memSession) ID() string {
	return session.id
}

func (locked *lockedMemSession) ID() string {
	return locked.session.id
}

func (session *memSession) DoWith(guarded func(LockedSession)) {
	locked := &lockedMemSession{session}
	session.lock.Lock()
	guarded(locked)
	locked.session = nil
	session.lock.Unlock()
}

func (locked *lockedMemSession) DoWith(guarded func(LockedSession)) {
	guarded(locked)
}

func (locked *lockedMemSession) Authenticator() auth.Authenticator {
	return locked.session.authenticator
}

func (locked *lockedMemSession) SetAuthenticator(newAuthenticator auth.Authenticator) {
	locked.session.authenticator = newAuthenticator
}

func generateRandomSessionID() (string, error) {
	bytes := make([]byte, 30)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}
