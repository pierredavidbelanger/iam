package identity

import (
	"context"
	"golang.org/x/oauth2"
	"net/http"
)

type TokenDecoder interface {
	DecodeToken(token string, dest interface{}) error
}

type Configuration struct {
	OAuth2Config      *oauth2.Config
	LoginPath         string
	LoginCallbackPath string
	TokenDecoder      TokenDecoder
}

func NewMiddleware(config Configuration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if r.URL.Path == config.LoginPath {

				authUrl := config.OAuth2Config.AuthCodeURL(r.URL.Query().Get("state"))

				w.Header().Add("Location", authUrl)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}

			if r.URL.Path == config.LoginCallbackPath {

				token, err := config.OAuth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				idToken, idTokenFound := token.Extra("id_token").(string)
				if !idTokenFound {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				idClaims := make(map[string]interface{})
				err = config.TokenDecoder.DecodeToken(idToken, &idClaims)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				r = r.WithContext(newContext(r.Context(), idClaims))
			}

			next.ServeHTTP(w, r)
		})
	}
}

type contextKey int

var idClaimsRequestContextKey contextKey

func newContext(ctx context.Context, value map[string]interface{}) context.Context {
	return context.WithValue(ctx, idClaimsRequestContextKey, value)
}

func FromContext(ctx context.Context) (map[string]interface{}, bool) {
	value, ok := ctx.Value(idClaimsRequestContextKey).(map[string]interface{})
	return value, ok
}
