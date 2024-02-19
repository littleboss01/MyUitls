package MyUitls

import "strings"

func Xor(data string, num int) string {
	var result strings.Builder
	for i := 0; i < len(data); i++ {
		result.WriteByte(data[i] ^ byte(num))
	}
	return result.String()
}
