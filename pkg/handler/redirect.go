package handler

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/pkg/errors"
)

func handleRedirect(h *handler, responseWriter http.ResponseWriter, request *http.Request) {
	authenticator, redirectURL, err := h.flow.NewAuthenticator(request.URL)
	if err != nil {
		internalServerError(errors.Wrap(err, "failed to create new authenticator"), responseWriter, request)
		return
	}

	session, err := h.sessions.NewSession(authenticator)
	if err != nil {
		internalServerError(errors.Wrap(err, "failed to create session"), responseWriter, request)
		return
	}

	statusCode := http.StatusTemporaryRedirect
	statusText := http.StatusText(statusCode)

	cookie := &http.Cookie{}
	*cookie = *h.sessionCookieTemplate
	cookie.Value = session.ID()

	glog.Infof("%s %s <<< %d %s - %s", request.RemoteAddr, request.RequestURI, statusCode, statusText, redirectURL)
	http.SetCookie(responseWriter, cookie)
	http.Redirect(responseWriter, request, redirectURL.String(), http.StatusTemporaryRedirect)
}
