package app

import (
	"net/url"
	"strconv"
	"time"
)

// Carry freshness requirements into login. Recheck positive maximum ages on
// return; remove one-shot requirements so a completed forced login cannot loop.
func oauthLoginRedirect(fields url.Values) string {
	login := url.Values{}
	if fields.Get("prompt") == "login" {
		login.Set("prompt", "login")
	}
	if fields.Has("max_age") {
		login.Set("max_age", fields.Get("max_age"))
	}
	fields.Del("prompt")
	if age, err := strconv.ParseUint(fields.Get("max_age"), 10, 64); err == nil && age == 0 {
		fields.Del("max_age")
	}
	login.Set("r", "/oauth2/authorize?"+fields.Encode())
	return "/login?" + login.Encode()
}

func upstreamAuthenticationFresh(claims upstreamClaims, state upstreamLoginState, started time.Time) bool {
	if !state.ForceLogin && state.MaxAge == nil {
		return true
	}
	if claims.AuthTime <= 0 {
		return false
	}
	// Allow the same bounded clock skew used for upstream token timestamps.
	minimum := started.Unix()
	if !state.ForceLogin && state.MaxAge != nil && *state.MaxAge != 0 {
		now := time.Now().Unix()
		minimum = now - int64(min(*state.MaxAge, uint64(now)))
	}
	return claims.AuthTime >= minimum-60
}
