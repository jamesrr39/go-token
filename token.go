package gotoken

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jamesrr39/goutil/errorsx"
)

const (
	JwtIDKey        = "id"
	JwtAccountIDKey = "account"
	JwtRoleIDsKey   = "roles"
)

type Token struct {
	ID        int64
	AccountID int64
	RoleIDs   []int64
	CreatedAt time.Time
}

func NewToken(id, accountID int64, roleIDs []int64, createdAt time.Time) *Token {
	return &Token{id, accountID, roleIDs, createdAt}
}

func (token *Token) ToJWTToken(hmacSecret []byte) (string, errorsx.Error) {
	roleIDs := token.RoleIDs
	if roleIDs == nil {
		roleIDs = []int64{}
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		JwtIDKey:        token.ID,
		JwtAccountIDKey: token.AccountID,
		JwtRoleIDsKey:   roleIDs,
		"nbf":           token.CreatedAt.Unix(),
	})
	tokenString, err := jwtToken.SignedString(hmacSecret)
	if err != nil {
		return "", errorsx.Wrap(err)
	}

	return tokenString, nil
}
