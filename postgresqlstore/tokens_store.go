package postgresqlstore

import (
	"database/sql"
	"time"

	gotoken "github.com/jamesrr39/go-token"
	"github.com/jamesrr39/go-token/webservice"
	"github.com/jamesrr39/goutil/errorsx"
)

type TokenStore struct{}

func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

func (s *TokenStore) CreateToken(tx *sql.Tx, accountID int64) (*gotoken.Token, errorsx.Error) {
	var err error

	token := &gotoken.Token{
		AccountID: accountID,
		CreatedAt: time.Now().UTC(),
	}

	row := tx.QueryRow(`
		INSERT INTO tokens (account_id, created_at)
		VALUES ($1, $2) RETURNING id`,
		accountID,
		token.CreatedAt,
	)

	err = row.Scan(&token.ID)
	if err != nil {
		return nil, errorsx.Wrap(err)
	}

	return token, nil
}

func DefaultCreateTokenFunc(db *sql.DB, tokenStore *TokenStore) webservice.CreateTokenFunc {
	return func(accountID int64) (*gotoken.Token, errorsx.Error) {
		tx, err := db.Begin()
		if err != nil {
			return nil, errorsx.Wrap(err)
		}
		defer tx.Rollback()

		token, err := tokenStore.CreateToken(tx, accountID)
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
