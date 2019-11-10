package token

import (
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

type KeyFinder interface {
	FindKeyById(string) (*jose.JSONWebKey, error)
	FindKeyByUse(string) (*jose.JSONWebKey, error)
}

type SignedCodec struct {
	KeyFinder KeyFinder
	Issuer    string
	Audience  string
	Duration  time.Duration
}

func (d *SignedCodec) DecodeToken(token string, dest interface{}) error {

	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return err
	}

	jwk, err := d.KeyFinder.FindKeyById(parsedToken.Headers[0].KeyID)
	if err != nil {
		return err
	}
	if jwk == nil {
		return fmt.Errorf("key id not found: %s", parsedToken.Headers[0].KeyID)
	}

	claims := jwt.Claims{}
	switch jwk.Key.(type) {
	case []byte:
		err = parsedToken.Claims(jwk, &claims, dest)
	default:
		err = parsedToken.Claims(jwk.Public(), &claims, dest)
	}
	if err != nil {
		return err
	}

	if d.Issuer != "" && claims.Issuer != d.Issuer {
		return fmt.Errorf("invalid token: unexpected issuer: %s", claims.Issuer)
	}

	if d.Audience != "" && !contains(claims.Audience, d.Audience) {
		return fmt.Errorf("invalid token: unexpected audience: %v", claims.Audience)
	}

	now := time.Now().Add(5 * time.Minute)

	if claims.Expiry != nil && claims.Expiry.Time().Before(now) {
		return fmt.Errorf("invalid token: expired: %s", claims.Expiry.Time().Format(time.RFC3339))
	}

	if claims.NotBefore != nil && claims.NotBefore.Time().After(now) {
		return fmt.Errorf("invalid token: before: %s", claims.NotBefore.Time().Format(time.RFC3339))
	}

	return nil
}

func (d *SignedCodec) EncodeToken(claims interface{}) (string, error) {

	key, err := d.KeyFinder.FindKeyByUse("sig")
	if err != nil {
		return "", err
	}

	signerOptions := &jose.SignerOptions{}
	signerOptions.WithType("JWT")
	signerOptions.WithHeader("kid", key.KeyID)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       key,
	}, signerOptions)
	if err != nil {
		return "", err
	}

	stdClaims := jwt.Claims{}

	if d.Issuer != "" {
		stdClaims.Issuer = d.Issuer
	}

	if d.Audience != "" {
		stdClaims.Audience = []string{d.Audience}
	}

	if d.Duration > 0 {
		stdClaims.Expiry = jwt.NewNumericDate(time.Now().Add(d.Duration))
	}

	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
