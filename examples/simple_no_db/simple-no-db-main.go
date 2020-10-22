package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/go-token/webservice"
	"github.com/jamesrr39/goutil/base64x"
	"github.com/jamesrr39/goutil/errorsx"
	"github.com/jamesrr39/goutil/logpkg"
	"github.com/jamesrr39/goutil/must"
)

const (
	// hard-coded for example. These should be provided through configurations/"secrets management"
	base64RootPassword       = "AGxYFfYABz0Q0bAypHH+IKdlKRMXigB80ZYUebVaF2JUmAtOBMSxYLAx0XhswuhnnTVXbYPSRsFXKhrQ0sM29KcuTUK623t33U0VOZKn+fA="
	base64HashedRootPassword = "JDJhJDEwJFJWTU9TaWZieTk5YXFJbW1ibkd0eU8uS0l0aTBWY0hZOGJPUUVOcjExMXM2WWhzWmN2YUxH"
	base64HmacSecret         = "upT6TCjETY6xH1NFx2ySKG4iZvJ9YpK/n19aRLFkHSZfFF5S7c7Mh2VgzdhtjaKzYCWG0mrMf2EXhac7yEjzhkpbjvbTroeYK2FJQ3L6oEw="

	addr = "localhost:9093"
)

func main() {
	logger := logpkg.NewLogger(os.Stderr, logpkg.LogLevelInfo)

	var lastTokenID uint64

	bcryptHashedToken, err := base64x.DecodeBase64(bytes.NewBufferString(base64HashedRootPassword))
	must.NoError(err)

	hmacSecret, err := base64x.DecodeBase64(bytes.NewBufferString(base64HmacSecret))
	must.NoError(err)

	createTokenFunc := func(accountID int64) (*gotoken.Token, errorsx.Error) {
		// no save to database here, just create a jwt token
		tokenID := atomic.AddUint64(&lastTokenID, 1)

		token := gotoken.NewToken(int64(tokenID), accountID, time.Now())
		log.Printf("created token: %#v\n", token)

		return token, nil
	}

	router := chi.NewRouter()

	router.Route("/api/", func(r chi.Router) {
		r.Route("/admin/", func(r chi.Router) {
			r.Use(webservice.RootTokenMiddleware(logger, bcryptHashedToken))
			r.Mount("/token/", webservice.NewTokenService(logger, createTokenFunc, hmacSecret))
		})
		r.Route("/v1/", func(r chi.Router) {
			r.Use(webservice.AuthTokenMiddleWare(logger, hmacSecret))
			r.Get("/*", handleAllGet)
		})
	})

	log.Printf("serving on %q\n", addr)
	log.Printf(`try out some requests:
curl -H 'Authorization: Bearer %s' -X POST --data '{"accountId": 123}' http://%s/api/admin/token/

curl -H 'Authorization: Bearer <token from response from request above>' http://%s/api/v1/a/b/c
`,
		base64RootPassword, addr, addr)
	http.ListenAndServe(addr, router)
}

func handleAllGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tokenID, err := webservice.GetIDFromCtx(ctx)
	must.NoError(err)

	accountID, err := webservice.GetAccountIDFromCtx(ctx)
	must.NoError(err)

	fmt.Fprintf(w, "hello, you are at %s. The token ID is %d and the account ID on the token is %d\n", r.URL.String(), tokenID, accountID)
}
