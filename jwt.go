package jwt

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"

	"encoding/json"
	"io/ioutil"

	"log"

	"github.com/dgrijalva/jwt-go"
)

type JWK struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

type Validator struct {
	publicKeys
}

type publicKeys struct {
	Keys []JWK
}

func NewValidatorWithKeysFromFile(filepath string) *Validator {
	fileBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatalf("failed to open file '%s': %s", filepath, err.Error())
	}

	var keys = publicKeys{}
	err = json.Unmarshal(fileBytes, &keys)
	if err != nil {
		log.Fatalf("failed to unmarshal '%s': %s", filepath, err.Error())
	}
	return &Validator{publicKeys: keys}
}

func (c *Validator) IsTokenValid(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		if kid, ok := token.Header["kid"]; ok {
			for _, k := range c.Keys {
				if k.Kid == kid {
					return publicKey(k)
				}
			}
		}
		return nil, fmt.Errorf("no matching kid for given token found")

	})

	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return false
	}

	return token.Valid
}

func publicKey(key JWK) (*rsa.PublicKey, error) {
	decN, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	n := big.NewInt(0)
	n.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}
