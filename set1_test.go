package cryptopals

import (
	"bytes"
	"reflect"
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

		actual := HexToBase64(input)
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
		aHex, err := EncodeHex(table.a)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.a, err)
		}

		bHex, err := EncodeHex(table.b)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.b, err)
		}

		expectedHex, err := EncodeHex(table.expected)
		if err != nil {
			t.Errorf("EncodeHex(%s) returned err: %s", table.expected, err)
		}

		actualHex, err := FixedXor(aHex, bHex)
		if !bytes.Equal(expectedHex, actualHex) {
			t.Errorf("FixedXor(%s, %s) returned '%s', expecting '%s'", table.a, table.b, table.expected, actualHex)
		}
	}
}

func TestDecodeSingle(t *testing.T) {
	type args struct {
		in []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
		{"main", args{[]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")}, []byte("Cooking MC's like a pound of bacon")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inHex, err := EncodeHex(tt.args.in)
			if err != nil {
				t.Errorf("EncodeHex() returned err: %v", err)
			}
			if got, err := DecodeSingle(inHex); !reflect.DeepEqual(got, tt.want) || err != nil {
				t.Errorf("DecodeSingle() = (%v, %v), want %v", string(got), err, tt.want)
			}
		})
	}
}
