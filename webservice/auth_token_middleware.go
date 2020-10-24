package webservice

import (
	"context"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/goutil/errorsx"
	"github.com/jamesrr39/goutil/logpkg"
)

func AuthTokenMiddleWare(logger *logpkg.Logger, hmacSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tokenString == "" {
				errorsx.HTTPError(w, logger, errorsx.Errorf("no token provided"), http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errorsx.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return hmacSecret, nil
			})
			if err != nil {
				errorsx.HTTPError(w, logger, errorsx.Wrap(err), http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				errorsx.HTTPError(w, logger, errorsx.Wrap(err), http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				errorsx.HTTPError(w, logger, errorsx.Wrap(err), http.StatusInternalServerError)
				return
			}

			// float64 -> int64
			id := int64(claims[gotoken.JwtIDKey].(float64))
			accountID := int64(claims[gotoken.JwtAccountIDKey].(float64))
			var roleIDs []int64
			for _, roleIDInterface := range claims[gotoken.JwtRoleIDsKey].([]interface{}) {
				roleIDs = append(roleIDs, int64(roleIDInterface.(float64)))
			}

			ctx = context.WithValue(ctx, gotoken.TokenIDCtxKey, id)
			ctx = context.WithValue(ctx, gotoken.TokenAccountIDCtxKey, accountID)
			ctx = context.WithValue(ctx, gotoken.TokenRoleIDsCtxKey, roleIDs)

			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
