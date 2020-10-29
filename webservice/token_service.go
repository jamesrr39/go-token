package webservice

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/goutil/errorsx"
	"github.com/jamesrr39/goutil/logpkg"
)

type TokenService struct {
	logger          *logpkg.Logger
	createTokenFunc CreateTokenFunc
	hmacSecret      []byte
	chi.Router
}

type CreateTokenFunc func(accountID int64, name string, roleIDs []int64) (*gotoken.Token, errorsx.Error)

func NewTokenService(logger *logpkg.Logger, createTokenFunc CreateTokenFunc, hmacSecret []byte) *TokenService {
	ts := &TokenService{logger, createTokenFunc, hmacSecret, chi.NewRouter()}

	ts.Post("/", ts.handlePost)

	return ts
}

func (s *TokenService) handlePost(w http.ResponseWriter, r *http.Request) {
	type requestBodyType struct {
		AccountID int64   `json:"accountId"`
		Name      string  `json:"name"`
		RoleIDs   []int64 `json:"roleIds"`
	}

	var requestBody requestBodyType
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		errorsx.HTTPError(w, s.logger, errorsx.Wrap(err), http.StatusInternalServerError)
		return
	}

	token, err := s.createTokenFunc(requestBody.AccountID, requestBody.Name, requestBody.RoleIDs)
	if err != nil {
		errorsx.HTTPError(w, s.logger, errorsx.Wrap(err), http.StatusInternalServerError)
		return
	}

	jwtToken, err := token.ToJWTToken(s.hmacSecret)
	if err != nil {
		errorsx.HTTPError(w, s.logger, errorsx.Wrap(err), http.StatusInternalServerError)
		return
	}

	type createTokenResponse struct {
		Token string `json:"token"`
	}

	render.JSON(w, r, createTokenResponse{
		Token: jwtToken,
	})
}
