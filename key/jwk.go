package key

import (
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"net/http"
	"sync"
)

func NewFinderFromWellKnownUrl(url string) *WellKnownUrlKeyFinder {
	return &WellKnownUrlKeyFinder{url: url}
}

func NewFinderFromKeySet(jwks jose.JSONWebKeySet) *JwksKeyFinder {
	return &JwksKeyFinder{jwks: jwks}
}

type JwksKeyFinder struct {
	jwks jose.JSONWebKeySet
}

func (f *JwksKeyFinder) FindKeyById(kid string) (*jose.JSONWebKey, error) {
	for _, key := range f.jwks.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}
	return nil, nil
}

func (f *JwksKeyFinder) FindKeyByUse(use string) (*jose.JSONWebKey, error) {
	for _, key := range f.jwks.Keys {
		if key.Use == use {
			return &key, nil
		}
	}
	return nil, nil
}

type WellKnownUrlKeyFinder struct {
	JwksKeyFinder
	url string
	rw  sync.RWMutex
}

func (f *WellKnownUrlKeyFinder) FindKeyById(kid string) (*jose.JSONWebKey, error) {
	return f.findKey(func() (*jose.JSONWebKey, error) {
		return f.JwksKeyFinder.FindKeyById(kid)
	})
}

func (f *WellKnownUrlKeyFinder) FindKeyByUse(use string) (*jose.JSONWebKey, error) {
	return f.findKey(func() (*jose.JSONWebKey, error) {
		return f.JwksKeyFinder.FindKeyByUse(use)
	})
}

func (f *WellKnownUrlKeyFinder) findKey(predicate func() (*jose.JSONWebKey, error)) (*jose.JSONWebKey, error) {

	// read lock
	f.rw.RLock()
	// find key
	key, err := predicate()
	f.rw.RUnlock()
	if err != nil {
		return nil, err
	}
	// happy path
	if key != nil {
		return key, nil
	}

	// write lock
	f.rw.Lock()
	defer f.rw.Unlock()

	// double check if key appear while we waited for the lock
	key, err = predicate()
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}

	// fetch and decode key set from URL
	res, err := http.Get(f.url)
	if err != nil {
		return nil, err
	}
	//noinspection GoUnhandledErrorResult
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&f.jwks)
	if err != nil {
		return nil, err
	}

	// find key
	key, err = predicate()
	if err != nil {
		return nil, err
	}

	return key, nil
}
