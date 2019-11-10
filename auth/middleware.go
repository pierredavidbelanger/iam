package auth

import (
	"context"
	"net/http"
)

type TokenFinder interface {
	FindToken(http.ResponseWriter, *http.Request) (string, error)
}

type tokenFinder struct {
	f func(http.ResponseWriter, *http.Request) (string, error)
}

func (t tokenFinder) FindToken(w http.ResponseWriter, r *http.Request) (string, error) {
	return t.f(w, r)
}

func TokenFinderFunc(f func(w http.ResponseWriter, r *http.Request) (string, error)) TokenFinder {
	return &tokenFinder{f: f}
}

type TokenDecoder interface {
	DecodeToken(token string, dest interface{}) error
}

type Configuration struct {
	TokenFinder  TokenFinder
	TokenDecoder TokenDecoder
}

func NewMiddleware(c Configuration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token, err := c.TokenFinder.FindToken(w, r)

			if err != nil {
				// todo
			} else if token != "" {

				claims := make(map[string]interface{})
				err = c.TokenDecoder.DecodeToken(token, &claims)
				if err != nil {
					// todo
				} else {

					r = r.WithContext(newContext(r.Context(), claims))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

type contextKey int

var principalRequestContextKey contextKey

func newContext(ctx context.Context, value map[string]interface{}) context.Context {
	return context.WithValue(ctx, principalRequestContextKey, value)
}

func FromContext(ctx context.Context) (map[string]interface{}, bool) {
	value, ok := ctx.Value(principalRequestContextKey).(map[string]interface{})
	return value, ok
}
