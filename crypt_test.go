package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	k1, err := Generate()
	assert.NoError(t, err)

	k2, err := Generate()
	assert.NoError(t, err)

	msg := []byte("Hello World")

	encrypted := k1.Encrypt(k2.PublicKey(), msg)
	pub, decrypted, err := k2.Decrypt(encrypted)
	if assert.NoError(t, err) {
		assert.Equal(t, k1.PublicKey(), pub)
		assert.Equal(t, msg, decrypted)
	}
}
