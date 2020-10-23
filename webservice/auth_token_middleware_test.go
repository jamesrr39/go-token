package webservice

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/goutil/base64x"
	"github.com/jamesrr39/goutil/logpkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleWare(t *testing.T) {
	hmacSecret := []byte("abcdef")
	logger := logpkg.NewLogger(os.Stderr, logpkg.LogLevelInfo)
	mw := AuthTokenMiddleWare(logger, hmacSecret)

	t.Run("unauthorized request", func(t *testing.T) {
		var err error

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("shouldn't reach this handler")
		})

		handler := mw(nextHandler)

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		handler.ServeHTTP(w, r)

		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("invalid token", func(t *testing.T) {
		var err error

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("shouldn't reach this handler")
		})

		handler := mw(nextHandler)

		token, err := base64x.EncodeBase64(bytes.NewBufferString("0123456abcde"))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		handler.ServeHTTP(w, r)

		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("authorized request", func(t *testing.T) {
		var err error

		var receivedTokenID int64
		var receivedAccountID int64
		var receivedRoleIDs []int64
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var err error

			receivedTokenID, err = GetIDFromCtx(ctx)
			require.NoError(t, err)

			receivedAccountID, err = GetAccountIDFromCtx(ctx)
			require.NoError(t, err)

			receivedRoleIDs, err = GetRoleIDsFromCtx(ctx)
			require.NoError(t, err)
		})

		handler := mw(nextHandler)

		expectedTokenID := int64(10001)
		expectedAccountID := int64(40)
		expectedRoleIDs := []int64{1, 54, 10}

		token := gotoken.NewToken(expectedTokenID, expectedAccountID, expectedRoleIDs, time.Time{})
		jwtToken, err := token.ToJWTToken(hmacSecret)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		r, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

		handler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedTokenID, receivedTokenID)
		assert.Equal(t, expectedAccountID, receivedAccountID)
		assert.Equal(t, expectedRoleIDs, receivedRoleIDs)

	})
}
