package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/jamesrr39/goutil/base64x"
	"github.com/jamesrr39/goutil/must"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := make([]byte, 80)

	_, err := rand.Read(password)
	must.NoError(err)

	hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	must.NoError(err)

	base64Password, err := base64x.EncodeBase64(bytes.NewBuffer(password))
	must.NoError(err)

	base64Hashed, err := base64x.EncodeBase64(bytes.NewBuffer(hashed))
	must.NoError(err)

	fmt.Printf(`Base64 Password:
%s

Base64 hashed password:
%s
`, base64Password, base64Hashed)
}
