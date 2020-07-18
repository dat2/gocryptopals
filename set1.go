package cryptopals

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"unicode"
)

func EncodeHex(src []byte) ([]byte, error) {
	dest := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dest, src)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

func encodeBase64(b byte) byte {
	if b < 26 {
		return byte('A') + b
	} else if b < 52 {
		return byte('a') + (b - 26)
	} else if b < 62 {
		return byte('0') + (b - 52)
	} else if b == 62 {
		return byte('+')
	} else if b == 63 {
		return byte('/')
	}
	panic(fmt.Sprintf("Received %d, unexpected.", b))
}

func roundToNearestMultiple(i, multiple int) int {
	return ((i + multiple - 1) / multiple) * multiple
}

func HexToBase64(s []byte) []byte {
	inputLen := len(s)

	// ensure it gets rounded to the nearest multiple of 4
	result := make([]byte, roundToNearestMultiple(inputLen*4/3, 4))

	j := 0
	for i := 0; i < inputLen; i += 3 {
		result[j] = encodeBase64(s[i] >> 2)
		if i+2 < inputLen {
			result[j+1] = encodeBase64(((s[i] & 0x03) << 4) ^ (s[i+1] >> 4))
			result[j+2] = encodeBase64(((s[i+1] & 0x0F) << 2) ^ (s[i+2] >> 6))
			result[j+3] = encodeBase64((s[i+2] & 0x3F))
		} else if i+1 < inputLen {
			result[j+1] = encodeBase64(((s[i] & 0x03) << 4) ^ (s[i+1] >> 4))
			result[j+2] = encodeBase64(((s[i+1] & 0x0F) << 2))
			result[j+3] = byte('=')
		} else {
			result[j+1] = encodeBase64(((s[i] & 0x03) << 4))
			result[j+2] = byte('=')
			result[j+3] = byte('=')
		}
		j += 4
	}
	return result
}

func FixedXor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("Length of %d != %d", len(a), len(b))
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func countLetterFrequency(in []byte) map[byte]int {
	letters := make(map[byte]int)
	for _, b := range in {
		if unicode.IsLetter(rune(b)) {
			letters[b] = letters[b] + 1
		}
	}
	return letters
}

type scoredResult struct {
	decoded []byte
	score   int
}

func newScoredResult(decoded []byte) scoredResult {
	score := 0
	freq := countLetterFrequency(decoded)
	for _, count := range freq {
		score += count
	}
	return scoredResult{decoded, score}
}

func DecodeSingle(in []byte) ([]byte, error) {
	scored := make([]scoredResult, 52)
	for b := byte('A'); b < byte('z'); b++ {
		decoded, err := FixedXor(in, bytes.Repeat([]byte{b}, len(in)))
		if err != nil {
			return []byte{}, fmt.Errorf("failed to xor: %w", err)
		}
		scored = append(scored, newScoredResult(decoded))
	}
	// sort in reverse
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	return scored[0].decoded, nil
}

func FindEncoded(in [][]byte) ([]byte, error) {
	results := make([][]byte, len(in))
	scored := make([]scoredResult, len(in))
	for i, slice := range in {
		result, err := DecodeSingle(slice)
		if err != nil {
			return []byte{}, err
		}
		results[i] = result
		scored[i] = newScoredResult(result)
	}
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	return scored[0].decoded, nil
}
