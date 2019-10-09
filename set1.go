package cryptopals

import (
	"encoding/hex"
	"fmt"
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

func HexToBase64(s []byte) ([]byte, error) {
	input_len := len(s)

	// ensure it gets rounded to the nearest multiple of 4
	result := make([]byte, roundToNearestMultiple(input_len*4/3, 4))

	j := 0
	for i := 0; i < input_len; i += 3 {
		result[j] = encodeBase64(s[i] >> 2)
		if i+2 < input_len {
			result[j+1] = encodeBase64(((s[i] & 0x03) << 4) ^ (s[i+1] >> 4))
			result[j+2] = encodeBase64(((s[i+1] & 0x0F) << 2) ^ (s[i+2] >> 6))
			result[j+3] = encodeBase64((s[i+2] & 0x3F))
		} else if i+1 < input_len {
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
	return result, nil
}
