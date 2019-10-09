package cryptopals

import (
	"bytes"
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
		{input: []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), expected: []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")},
	}

	for _, table := range tables {
		input, err := EncodeHex(table.input)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.input, err)
		}

		actual, err := HexToBase64(input)
		if err != nil {
			t.Errorf("HexToBase64(%s) returned err: %s", table.input, err)
		}
		if !bytes.Equal(table.expected, actual) {
			t.Errorf("HexToBase64(%s) returned '%s', expecting '%s'", table.input, actual, table.expected)
		}
	}
}
