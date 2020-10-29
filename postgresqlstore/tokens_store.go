package postgresqlstore

import (
	"database/sql"
	"time"

	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/go-token/webservice"
	"github.com/jamesrr39/goutil/errorsx"
	"github.com/lib/pq"
)

type TokenStore struct{}

func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

func (s *TokenStore) CreateToken(tx *sql.Tx, token *gotoken.Token) errorsx.Error {
	var err error

	row := tx.QueryRow(`
		INSERT INTO tokens (account_id, name, role_ids, created_at)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		token.AccountID,
		token.Name,
		pq.Array(token.RoleIDs),
		token.CreatedAt,
	)

	err = row.Scan(&token.ID)
	if err != nil {
		return errorsx.Wrap(err)
	}

	return nil
}

func DefaultCreateTokenFunc(db *sql.DB, tokenStore *TokenStore) webservice.CreateTokenFunc {
	return func(accountID int64, name string, roleIDs []int64) (*gotoken.Token, errorsx.Error) {
		tx, err := db.Begin()
		if err != nil {
			return nil, errorsx.Wrap(err)
		}
		defer tx.Rollback()

		token := gotoken.NewToken(0, accountID, name, roleIDs, time.Now().UTC())

		err = tokenStore.CreateToken(tx, token)
		if err != nil {
			return nil, errorsx.Wrap(err)
		}

		err = tx.Commit()
		if err != nil {
			return nil, errorsx.Wrap(err)
		}

		return token, nil
	}
}
