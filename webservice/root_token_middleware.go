package webservice

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/jamesrr39/goutil/base64x"
	"github.com/jamesrr39/goutil/errorsx"
	"github.com/jamesrr39/goutil/logpkg"
	"golang.org/x/crypto/bcrypt"
)

// RootTokenMiddleware is a middleware that checks for a fixed password
func RootTokenMiddleware(logger *logpkg.Logger, bcryptHashedRootToken []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			var err error

			base64EncodedPassword := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if base64EncodedPassword == "" {
				errorsx.HTTPError(w, logger, errorsx.Errorf("no token supplied"), http.StatusUnauthorized)
				return
			}

			password, err := base64x.DecodeBase64(bytes.NewBufferString(base64EncodedPassword))
			if err != nil {
				errorsx.HTTPError(w, logger, errorsx.Wrap(err), http.StatusUnauthorized)
				return
			}

			err = bcrypt.CompareHashAndPassword(bcryptHashedRootToken, password)
			if err != nil {
				errorsx.HTTPError(w, logger, errorsx.Wrap(err), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
