package cryptopals

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	tables := []struct {
		input    []byte
		expected []byte
	}{
		// Wikipedia
		// Man, Ma, M
		{input: []byte("4d616e"), expected: []byte("TWFu")},
		{input: []byte("4d61"), expected: []byte("TWE=")},
		{input: []byte("4d"), expected: []byte("TQ==")},
		// cryptopals example
		// https://cryptopals.com/sets/1/challenges/1
		{input: []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), expected: []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")},
	}

	for _, table := range tables {
		input, err := EncodeHex(table.input)
		assert.Nil(t, err)
		actual := HexToBase64(input)
		assert.Equal(t, table.expected, actual)
	}
}

func TestFixedXor(t *testing.T) {
	// https://cryptopals.com/sets/1/challenges/2
	a, err := EncodeHex([]byte("1c0111001f010100061a024b53535009181c"))
	assert.Nil(t, err)

	b, err := EncodeHex([]byte("686974207468652062756c6c277320657965"))
	assert.Nil(t, err)

	expected, err := EncodeHex([]byte("746865206b696420646f6e277420706c6179"))
	assert.Nil(t, err)

	actualHex, err := FixedXor(a, b)
	assert.Nil(t, err)
	assert.Equal(t, expected, actualHex)
}

func TestDecodeSingle(t *testing.T) {
	// https://cryptopals.com/sets/1/challenges/3
	challenge, err := EncodeHex([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	assert.Nil(t, err)

	actual, err := DecodeSingle(challenge)
	assert.Nil(t, err)
	assert.Equal(t, actual, []byte("Cooking MC's like a pound of bacon"))
}
