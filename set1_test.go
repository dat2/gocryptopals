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
		// cryptopals example
		// https://cryptopals.com/sets/1/challenges/1
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

func TestFixedXor(t *testing.T) {
	tables := []struct {
		a        []byte
		b        []byte
		expected []byte
	}{
		// https://cryptopals.com/sets/1/challenges/2
		{a: []byte("1c0111001f010100061a024b53535009181c"), b: []byte("686974207468652062756c6c277320657965"), expected: []byte("746865206b696420646f6e277420706c6179")},
	}

	for _, table := range tables {
		a_hex, err := EncodeHex(table.a)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.a, err)
		}

		b_hex, err := EncodeHex(table.b)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.b, err)
		}

		expected_hex, err := EncodeHex(table.expected)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.expected, err)
		}

		actual_hex, err := FixedXor(a_hex, b_hex)
		if !bytes.Equal(expected_hex, actual_hex) {
			t.Errorf("FixedXor(%s, %s) returned '%s', expecting '%s'", table.a, table.b, table.expected, actual_hex)
		}
	}
}
