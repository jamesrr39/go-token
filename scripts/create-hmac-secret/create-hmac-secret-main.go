package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/jamesrr39/goutil/base64x"
)

func main() {
	secretLenBits := 256

	b := make([]byte, secretLenBits/8)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	base64Secret, err := base64x.EncodeBase64(bytes.NewBuffer(b))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Base64 HMAC secret:\n%s\n", base64Secret)
}
