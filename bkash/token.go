package bkash

import (
	"time"
)

// expiryDelta determines how earlier a Token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
//
// According to bkash Documentation [https://developer.bka.sh/docs/token-management-overview-3],
// Before the end of the current Token lifetime (at the 50th/55th minute), call the Refresh Token API to get a new Token against your existing Token.
const expiryDelta = 10 * time.Minute

// Token represents the credentials used to authorize
// the requests to bkash.
type Token struct {
	// TokenType is the Token type for whom the Token is being granted. Default value is "Bearer".
	TokenType string

	// ExpiresIn is the expiry time of the Token. By default, the lifetime is 3600 seconds.
	ExpiresIn time.Time

	// IdToken is the corresponding Token value to be used for future authorization.
	IdToken string

	// RefreshToken should be used in Refresh Token API for getting a new Token against the current Token value.
	RefreshToken string
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.IdToken != "" && !t.expired()
}

// expired reports whether the Token is expired.
// t must be non-nil.
func (t *Token) expired() bool {
	if t.ExpiresIn.IsZero() {
		return false
	}
	return t.ExpiresIn.Round(0).Add(-expiryDelta).Before(time.Now())
}

// tokenJSON is the struct representing the HTTP response from bkash returning a Token in JSON form.
type tokenJSON struct {
	TokenType     string `json:"token_type,omitempty"`
	ExpiresIn     int    `json:"expires_in,omitempty"`
	IdToken       string `json:"id_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	StatusCode    string `json:"statusCode,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

func (tj *tokenJSON) expiry() (t time.Time) {
	if v := tj.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}
