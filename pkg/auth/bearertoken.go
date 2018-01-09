package auth

import "net/http"
import "fmt"
import "net/url"

type BearerToken struct {
	Value string
}

const (
	authorizationHeader = "Authorization"
	bearerTokenPrefix   = "Bearer "
)

func (bearerToken *BearerToken) Authenticate(request *http.Request) (auth Authentication, newAuthenticator Authenticator, err error) {
	return bearerToken, nil, nil
}

func (bearerToken *BearerToken) InjectInto(request *http.Request) (redirectURL *url.URL) {
	request.Header.Set(authorizationHeader, fmt.Sprintf("%s%s", bearerTokenPrefix, bearerToken.Value))
	return nil
}
