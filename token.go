package gotoken

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jamesrr39/goutil/errorsx"
)

const (
	JwtIDKey        = "id"
	JwtAccountIDKey = "account"
)

type Token struct {
	ID        int64
	AccountID int64
	CreatedAt time.Time
}

func NewToken(id, accountID int64, createdAt time.Time) *Token {
	return &Token{id, accountID, createdAt}
}

func (token *Token) ToJWTToken(hmacSecret []byte) (string, errorsx.Error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		JwtIDKey:        token.ID,
		JwtAccountIDKey: token.AccountID,
		"nbf":           token.CreatedAt.Unix(),
	})
	tokenString, err := jwtToken.SignedString(hmacSecret)
	if err != nil {
		return "", errorsx.Wrap(err)
	}

	return tokenString, nil
}
