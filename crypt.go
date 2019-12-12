package crypt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/nacl/box"
)

const (
	// KeySize is the size of an encryption key in bytes
	KeySize = 32
	// NonceSize is the size of a nonce in bytes
	NonceSize = 24
)

type (
	// PrivateKey is a private encryption key
	PrivateKey [KeySize * 2]byte
)

// Generate generates a new PrivateKey.
func Generate() (PrivateKey, error) {
	var key PrivateKey

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return key, err
	}

	copy(key[:], priv[:])
	copy(key[KeySize:], pub[:])
	return key, nil
}

// NewKey creates a new key from a base58 string.
func NewPrivateKey(str string) (key PrivateKey, err error) {
	bs, err := base58.Decode(str)
	if err != nil {
		return key, err
	}
	if len(bs) != KeySize {
		return key, errors.New("invalid key")
	}
	copy(key[:], bs)
	return key, nil
}

// Decrypt decrypts data that was encrypted via a private key. The peer's public key is sent along with the data.
func (key PrivateKey) Decrypt(data []byte) (PublicKey, []byte, error) {
	var priv [KeySize]byte
	copy(priv[:], key[:])

	if len(data) < KeySize {
		return PublicKey{}, nil, fmt.Errorf("invalid message: expected public key")
	}

	var pub [KeySize]byte
	copy(pub[:], data[:])
	data = data[KeySize:]

	if len(data) < NonceSize {
		return pub, nil, fmt.Errorf("invalid message: expected nonce")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], data[:])
	data = data[NonceSize:]

	opened, ok := box.Open(nil, data, &nonce, &pub, &priv)
	if !ok {
		return pub, nil, fmt.Errorf("invalid message: nacl box open failed")
	}

	return pub, opened, nil
}

// Encrypt encrypts data using the private key intended for the peer public key.
func (key PrivateKey) Encrypt(peersPublicKey PublicKey, data []byte) []byte {
	var priv [KeySize]byte
	copy(priv[:], key[:KeySize])

	var pub [KeySize]byte
	copy(pub[:], peersPublicKey[:])

	nonce := generateNonce()
	sealed := box.Seal(nil, data, &nonce, &pub, &priv)

	result := make([]byte, 0, len(pub)+len(nonce)+len(sealed))
	result = append(result, key[KeySize:]...)
	result = append(result, nonce[:]...)
	result = append(result, sealed...)
	return result
}

func (key PrivateKey) PublicKey() PublicKey {
	var pub PublicKey
	copy(pub[:], key[KeySize:])
	return pub
}

// String returns the base58 encoded representation of the private key.
func (key PrivateKey) String() string {
	return base58.Encode(key[:])
}

// MarshalYAML marshales the key for use in a YAML file.
func (key PrivateKey) MarshalYAML() (interface{}, error) {
	return key.String(), nil
}

// UnmarshalYAML unmarshales the key from a YAML file.
func (key *PrivateKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	*key, err = NewPrivateKey(str)
	if err != nil {
		return err
	}
	return nil
}

type (
	// PublicKey is a public encryption key
	PublicKey [KeySize]byte
)

// NewKey creates a new key from a base58 string.
func NewPublicKey(str string) (key PublicKey, err error) {
	bs, err := base58.Decode(str)
	if err != nil {
		return key, err
	}
	if len(bs) != KeySize {
		return key, errors.New("invalid key")
	}
	copy(key[:], bs)
	return key, nil
}

// String returns the base58 encoded public key.
func (key PublicKey) String() string {
	return base58.Encode(key[:])
}

// MarshalYAML marshals the public key for a YAML file.
func (key PublicKey) MarshalYAML() (interface{}, error) {
	return key.String(), nil
}

// UnmarshalYAML unmarshals the public key from a YAML file.
func (key *PublicKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	*key, err = NewPublicKey(str)
	if err != nil {
		return err
	}
	return nil
}

type (
	// Nonce is a number used once.
	Nonce = [NonceSize]byte
)

func generateNonce() Nonce {
	var nonce Nonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}
