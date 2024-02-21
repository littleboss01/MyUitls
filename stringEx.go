package MyUitls

import "strings"

func Xor(data string, num int) string {
	var result strings.Builder
	for i := 0; i < len(data); i++ {
		result.WriteByte(data[i] ^ byte(num))
	}
	return result.String()
}

func Xor_ex(data string, num int) string {
	result := make([]rune, len(data))
	for i, c := range data {
		if i%2 == 0 {
			result[i] = c ^ 3
		} else {
			result[i] = c ^ 5
		}
	}
	for i := range result {
		result[i] ^= rune(num)
	}
	return string(result)
}
