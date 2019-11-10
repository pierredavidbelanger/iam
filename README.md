# iam
Code repository of useful bits of Go code related to authentication, identification, jwt, session

```go

idMiddleware := identity.NewMiddleware(identity.Configuration{
    OAuth2Config: &oauth2.Config{
        ClientID:     "...",
        ClientSecret: "...",
        Endpoint: oauth2.Endpoint{
            AuthURL:   "https://myapp.auth0.com/authorize",
            TokenURL:  "https://myapp.auth0.com/oauth/token",
            AuthStyle: oauth2.AuthStyleAutoDetect,
        },
        RedirectURL: "http://localhost:3000/login/callback",
        Scopes:      []string{"openid", "profile"},
    },
    LoginPath:         "/login",
    LoginCallbackPath: "/login/callback",
    TokenDecoder: &token.SignedCodec{
        KeyFinder: key.NewFinderFromWellKnownUrl("https://myapp.auth0.com/.well-known/jwks.json"),
        Issuer:    "https://myapp.auth0.com/",
        Audience:  "...",
    },
})

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    if r.URL.Path == "/login/callback" {

        idClaims, idClaimsExists := identity.FromContext(r.Context())
        if !idClaimsExists {
            return
        }

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