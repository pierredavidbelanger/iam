# iam
Code repository of useful bits of Go code related to authentication, identification, jwt, session

```go
oauth2Config := &oauth2.Config{
    ClientID:     "...",
    ClientSecret: "...",
    Endpoint: oauth2.Endpoint{
        AuthURL:   "https://myapp.auth0.com/authorize",
        TokenURL:  "https://myapp.auth0.com/oauth/token",
        AuthStyle: oauth2.AuthStyleAutoDetect,
    },
    RedirectURL: "http://localhost:3000/login/callback",
    Scopes:      []string{"openid", "profile"},
}

keyFinder := key.NewFinderFromWellKnownUrl("https://myapp.auth0.com/.well-known/jwks.json")

tokenDecoder := &token.SignedDecoder{
    KeyFinder: keyFinder,
    Issuer:    "https://myapp.auth0.com/",
    Audience:  oauth2Config.ClientID,
}

idMiddleware := identity.NewMiddleware(identity.Configuration{
    OAuth2Config:      oauth2Config,
    LoginPath:         "/login",
    LoginCallbackPath: "/login/callback",
    TokenDecoder:      tokenDecoder,
})

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    if r.URL.Path == "/login/callback" {

        idClaims, _ := identity.FromContext(r.Context())

        //noinspection GoUnhandledErrorResult
        fmt.Fprintf(w, "id claims: %#v", idClaims)

        return
    }

    b := make([]byte, 16)
    rand.Read(b)
    state := base64.URLEncoding.EncodeToString(b)

    //noinspection GoUnhandledErrorResult
    fmt.Fprintf(w, "<a href='/login?state=%s'>login</a>", state)
})

http.Handle("/", idMiddleware(handler))

log.Fatal(http.ListenAndServe(":3000", nil))
```