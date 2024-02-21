package MyUitls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func AesEncrypt2(origData []byte) string {
	key := []byte("LxDAzJ5qL#UJ\\nwM")
	//key := HexToBytes("4c7844417a4a35714c23554a5c6e774d")
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	blockSize := block.BlockSize()
	origData = pkcs7Padding(origData, blockSize)
	iv := make([]byte, aes.BlockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted)
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func RsaEncryptWithPublicKey(pubKeyStr string, plaintext []byte, outType int) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return "", err
	}

	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	// 分块加密
	blockSize := pub.Size() - 11
	encrypted := make([]byte, 0)
	for len(plaintext) > 0 {
		chunk := plaintext
		if len(chunk) > blockSize {
			chunk = chunk[:blockSize]
		}
		encryptedChunk, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, chunk, nil)
		if err != nil {
			return "", err
		}
		encrypted = append(encrypted, encryptedChunk...)
		plaintext = plaintext[len(chunk):]
	}

	if outType == 1 { //hex
		return fmt.Sprintf("%x", encrypted), nil
	} else if outType == 2 { //base64
		return base64.StdEncoding.EncodeToString(encrypted), nil
	} else {
		return string(encrypted), nil
	}
}

func RsaDecryptWithPrivateKey(privKeyStr string, ciphertext string, outType int) ([]byte, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyStr)
	if err != nil {
		return nil, err
	}

	privintface, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	priv := privintface.(*rsa.PrivateKey)
	var encrypted []byte
	if outType == 1 { //hex
		encrypted, err = hex.DecodeString(ciphertext)
		if err != nil {
			return nil, err
		}
	} else if outType == 2 { //base64
		encrypted, err = base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			return nil, err
		}
	} else {
		encrypted = []byte(ciphertext)
	}

	// 分块解密
	blockSize := priv.PublicKey.Size()
	plaintext := make([]byte, 0)
	for len(encrypted) > 0 {
		chunk := encrypted
		if len(chunk) > blockSize {
			chunk = chunk[:blockSize]
		}
		decryptedChunk, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, chunk, nil)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, decryptedChunk...)
		encrypted = encrypted[len(chunk):]
	}

	return plaintext, nil
}

// buye[] 用{1,2}的方式输出字符串
func Bytes2outputString(bytes []byte) (string, error) {
	var byteStrings = make([]string, len(bytes))
	for i, b := range bytes {
		byteStrings[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join(byteStrings, ","), nil
}

func AuthEx() {
	var str string
	args := os.Args
	if len(args) > 1 {
		str = args[1]
	} else {
		os.Exit(0)
	}
	var jsonStr string
	var weekInt int
	if len(str) > 0 {
		var data map[string]interface{}
		err := json.Unmarshal([]byte(str), &data)
		if err != nil {
			//取出星期几
			week := time.Now().Weekday()
			//转为整数
			weekInt = int(week)
			jsonStr = Xor(str, weekInt)
			json.Unmarshal([]byte(jsonStr), &data)
		}
		//data["ip"]强转bool
		ip, ok := data["ip"].(bool)
		if !ok {
			ip = true
		}
		isok, jsonData := Auth(ip, jsonStr)
		if !isok {
			//关闭
			os.Exit(0)
		} else {
			fmt.Println(Xor(jsonData, weekInt))
		}
	} else {
		//文件路径,win在c:\user\username\下,linux在/home/username/下
		var path string
		if IsWindows() {
			//path = "c:\\users\\configImapApi.json"
			path = string([]byte{99, 58, 92, 117, 115, 101, 114, 115, 92, 99, 111, 110, 102, 105, 103, 73, 109, 97, 112, 65, 112, 105, 46, 106, 115, 111, 110})
		} else {
			//path= "/home/configImapApi.json"
			path = string([]byte{47, 104, 111, 109, 101, 47, 99, 111, 110, 102, 105, 103, 73, 109, 97, 112, 65, 112, 105, 46, 106, 115, 111, 110})
		}
		//读取当前目录下的config.json文件
		file, _ := os.Open(path)
		defer file.Close()
		//读取文件内容
		data, err := ioutil.ReadAll(file)
		if err != nil {
			//fmt.Println("Error:", err)
			return
		}
		isok, jsonData := Auth(true, string(data))
		if isok {
			//写入json
			err := ioutil.WriteFile(path, []byte(jsonData), 0644)
			if err != nil {
				//fmt.Println("Error:", err)
				return
			}
			return
		}
	}
}

func AuthEx2() {
	var str string
	args := os.Args
	if len(args) > 1 {
		str = args[1]
	} else {
		os.Exit(0)
	}
	var jsonStr string
	var weekInt int
	if len(str) > 0 {
		//取出星期几
		week := time.Now().Weekday()
		//转为整数
		weekInt = int(week)
		jsonStr = Xor_ex(str, weekInt)

		ip := strings.Contains(jsonStr, "ip")
		//expirationTime  + machineCode + ip &拼接
		arr := strings.Split(jsonStr, "&")
		if len(arr) == 3 {
			expirationTime := arr[0]
			machineCode := arr[1]
			if IsExpirationTime(expirationTime) {
				if GetMachineCode(ip, true, true, true) == machineCode {
					return
				}
			}
		}
		os.Exit(0)
	} else {
		//文件路径,win在c:\user\username\下,linux在/home/username/下
		var path string
		if IsWindows() {
			//path = "c:\\users\\configImapApi.json"
			path = string([]byte{99, 58, 92, 117, 115, 101, 114, 115, 92, 99, 111, 110, 102, 105, 103, 73, 109, 97, 112, 65, 112, 105, 46, 106, 115, 111, 110})
		} else {
			//path= "/home/configImapApi.json"
			path = string([]byte{47, 104, 111, 109, 101, 47, 99, 111, 110, 102, 105, 103, 73, 109, 97, 112, 65, 112, 105, 46, 106, 115, 111, 110})
		}
		//读取当前目录下的config.json文件
		file, _ := os.Open(path)
		defer file.Close()
		//读取文件内容
		data, err := ioutil.ReadAll(file)
		if err != nil {
			//fmt.Println("Error:", err)
			return
		}
		str = string(data) + "&" + GetMachineCode(true, true, true, true) + "&" + "ip"
		//写入json
		err = ioutil.WriteFile(path, []byte(str), 0644)
		if err != nil {
			//fmt.Println("Error:", err)
			return
		}
		return
	}
}

func Auth(是否外网ip bool, str string) (bool, string) {
	//fmt.Println(bytes2outputString([]byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCycQd2uM/D3xyW4JC0IRWkey8DUQiopQRS0wlVhuDZIg/eDLf9HApZ2/11VJjZ8exDGW/AAAyMCuCpfnOaLgdkHp8fJz8OgO3fYSt/BOluUAVeWDe9vo4aNsXIurid6LLcUfaNunGIQNSyx4dJcTIrjSK8wDsYONwgqQLqqQYoD4O1jtYR58Y2JK1ySUMy7t5BYvSOPzo+Ui1mDDuO2467qUTCjuVLPEqnJ/WK5v4cGYI0HQQuNqaviMeNnxTlGGCeHzAcHy1gxSiPiGZrf5/YQ7UYb+zD5Be2jQhTHkmYCSWzgVMDFLMyn8BsU4QujbzlJXTiBknRZlBojmSpQpqDAgMBAAECggEAA+eJPEXK9gQ5wetj/y0CJjkzzCTHxbjmoVFQ0PhEjzu5kShCFl24tEKmBx00wwASJV23HkJiA+ZxCARmTydWrhAldy8KqCyWB98+bmcTHIDPvUK85X/36AbuyPec9oeS8lMwy+UaetrATLEk+qxpZp6N9gdWw67q0iQgljXglpvG7/k4n+jYUOhn5PM1QOA/hZOqUQR/GHUFd9/ay9CIHd9XV7zv39EbGVe2F9fUKbwK4cnyMf7243Z/RYSpDYDNsPyBvP8OENl8+TC2vR+SVX39P36aMA896qFmT1BPznLSzRz7pCQTDpHAsv/2BjU0ex7fvkG1KBklvupUZ7jBIQKBgQDdnFS+ZQHb4qWHGoPJZHlGWJF/opMruqdH8k3M6GIYKylHgs8hwtofXq8qEUxRd9CqxzCF7rSVPrqBTa1FjK/sAgzqQbgmEYLqx8T3XH9NWxt29cm6BEoiZwWBs2DtFBlrnz3wXpB+eX6tl444UDWsU20EJmN8LIfraTILgo7o6wKBgQDOIcSEuo94eTbiQzkfGj3S2lMVHHEf1tZ4CXdCywNLSkJcYwviGpiiGTKO23KvOBBRkHr0y/ngcw7Eo+3H0Xiqj4ocKvPe+xOAEbop0j+dopbLQnPpb7m9RxUaq2lBmfXuOAGOAFPKkP7tkHUix0YW8BhUroX8zvIPS8En3rquyQKBgQCD19QbCeDXProX7NBm6p20GlFFzCUeqQeIqEFdHQvvMQ53+vzcKx619xDjSDNNbKj6UVMu+1r4R7+R2fKyJActs/KXE85I57Ypk/w85gzeqstmNMh1IMQyP3RpO5z4rzKIcs7YyInSlNmm0TnNivrDsUZ0Z5pcb+nVRlp9uojnTQKBgCi3/uwBNmoj97WGdfgw5NmMCzF2ZtpVRBR+OjLVi5cJ2kYJwsUtX81VkOkrbGI0fvS9x6wnxvqRf+9UOppoRJ/crvmVeosnqdh4p/+u6qYnAgaw39jTGyvKqN6V0bsFwNEH+zaj1emD7vfau2jdWHkbgJLpzsn7z1E6M7O+ib4RAoGAX5oNfzj1Os6KxkvUTOOuifSShIbbvKt45Vn5WEHZ4yF+Y5grhxWys3r1JZAWEvG/Hkf0g415zrsxLV/d0aH4EKLI2WT8sMfd4roIliOCorGi+itsHcOpwJ0zfidkkwfE/Pn0wW88MmmI2LY7CtqGv8Bueya6191/oe5FbgGbW2M=")))
	//fmt.Println((bytes2outputString([]byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnEHdrjPw98cluCQtCEVpHsvA1EIqKUEUtMJVYbg2SIP3gy3/RwKWdv9dVSY2fHsQxlvwAAMjArgqX5zmi4HZB6fHyc/DoDt32ErfwTpblAFXlg3vb6OGjbFyLq4neiy3FH2jbpxiEDUsseHSXEyK40ivMA7GDjcIKkC6qkGKA+DtY7WEefGNiStcklDMu7eQWL0jj86PlItZgw7jtuOu6lEwo7lSzxKpyf1iub+HBmCNB0ELjamr4jHjZ8U5Rhgnh8wHB8tYMUoj4hma3+f2EO1GG/sw+QXto0IUx5JmAkls4FTAxSzMp/AbFOELo285SV04gZJ0WZQaI5kqUKagwIDAQAB"))))

	privateKey := []byte{77, 73, 73, 69, 118, 81, 73, 66, 65, 68, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 83, 67, 66, 75, 99, 119, 103, 103, 83, 106, 65, 103, 69, 65, 65, 111, 73, 66, 65, 81, 67, 121, 99, 81, 100, 50, 117, 77, 47, 68, 51, 120, 121, 87, 52, 74, 67, 48, 73, 82, 87, 107, 101, 121, 56, 68, 85, 81, 105, 111, 112, 81, 82, 83, 48, 119, 108, 86, 104, 117, 68, 90, 73, 103, 47, 101, 68, 76, 102, 57, 72, 65, 112, 90, 50, 47, 49, 49, 86, 74, 106, 90, 56, 101, 120, 68, 71, 87, 47, 65, 65, 65, 121, 77, 67, 117, 67, 112, 102, 110, 79, 97, 76, 103, 100, 107, 72, 112, 56, 102, 74, 122, 56, 79, 103, 79, 51, 102, 89, 83, 116, 47, 66, 79, 108, 117, 85, 65, 86, 101, 87, 68, 101, 57, 118, 111, 52, 97, 78, 115, 88, 73, 117, 114, 105, 100, 54, 76, 76, 99, 85, 102, 97, 78, 117, 110, 71, 73, 81, 78, 83, 121, 120, 52, 100, 74, 99, 84, 73, 114, 106, 83, 75, 56, 119, 68, 115, 89, 79, 78, 119, 103, 113, 81, 76, 113, 113, 81, 89, 111, 68, 52, 79, 49, 106, 116, 89, 82, 53, 56, 89, 50, 74, 75, 49, 121, 83, 85, 77, 121, 55, 116, 53, 66, 89, 118, 83, 79, 80, 122, 111, 43, 85, 105, 49, 109, 68, 68, 117, 79, 50, 52, 54, 55, 113, 85, 84, 67, 106, 117, 86, 76, 80, 69, 113, 110, 74, 47, 87, 75, 53, 118, 52, 99, 71, 89, 73, 48, 72, 81, 81, 117, 78, 113, 97, 118, 105, 77, 101, 78, 110, 120, 84, 108, 71, 71, 67, 101, 72, 122, 65, 99, 72, 121, 49, 103, 120, 83, 105, 80, 105, 71, 90, 114, 102, 53, 47, 89, 81, 55, 85, 89, 98, 43, 122, 68, 53, 66, 101, 50, 106, 81, 104, 84, 72, 107, 109, 89, 67, 83, 87, 122, 103, 86, 77, 68, 70, 76, 77, 121, 110, 56, 66, 115, 85, 52, 81, 117, 106, 98, 122, 108, 74, 88, 84, 105, 66, 107, 110, 82, 90, 108, 66, 111, 106, 109, 83, 112, 81, 112, 113, 68, 65, 103, 77, 66, 65, 65, 69, 67, 103, 103, 69, 65, 65, 43, 101, 74, 80, 69, 88, 75, 57, 103, 81, 53, 119, 101, 116, 106, 47, 121, 48, 67, 74, 106, 107, 122, 122, 67, 84, 72, 120, 98, 106, 109, 111, 86, 70, 81, 48, 80, 104, 69, 106, 122, 117, 53, 107, 83, 104, 67, 70, 108, 50, 52, 116, 69, 75, 109, 66, 120, 48, 48, 119, 119, 65, 83, 74, 86, 50, 51, 72, 107, 74, 105, 65, 43, 90, 120, 67, 65, 82, 109, 84, 121, 100, 87, 114, 104, 65, 108, 100, 121, 56, 75, 113, 67, 121, 87, 66, 57, 56, 43, 98, 109, 99, 84, 72, 73, 68, 80, 118, 85, 75, 56, 53, 88, 47, 51, 54, 65, 98, 117, 121, 80, 101, 99, 57, 111, 101, 83, 56, 108, 77, 119, 121, 43, 85, 97, 101, 116, 114, 65, 84, 76, 69, 107, 43, 113, 120, 112, 90, 112, 54, 78, 57, 103, 100, 87, 119, 54, 55, 113, 48, 105, 81, 103, 108, 106, 88, 103, 108, 112, 118, 71, 55, 47, 107, 52, 110, 43, 106, 89, 85, 79, 104, 110, 53, 80, 77, 49, 81, 79, 65, 47, 104, 90, 79, 113, 85, 81, 82, 47, 71, 72, 85, 70, 100, 57, 47, 97, 121, 57, 67, 73, 72, 100, 57, 88, 86, 55, 122, 118, 51, 57, 69, 98, 71, 86, 101, 50, 70, 57, 102, 85, 75, 98, 119, 75, 52, 99, 110, 121, 77, 102, 55, 50, 52, 51, 90, 47, 82, 89, 83, 112, 68, 89, 68, 78, 115, 80, 121, 66, 118, 80, 56, 79, 69, 78, 108, 56, 43, 84, 67, 50, 118, 82, 43, 83, 86, 88, 51, 57, 80, 51, 54, 97, 77, 65, 56, 57, 54, 113, 70, 109, 84, 49, 66, 80, 122, 110, 76, 83, 122, 82, 122, 55, 112, 67, 81, 84, 68, 112, 72, 65, 115, 118, 47, 50, 66, 106, 85, 48, 101, 120, 55, 102, 118, 107, 71, 49, 75, 66, 107, 108, 118, 117, 112, 85, 90, 55, 106, 66, 73, 81, 75, 66, 103, 81, 68, 100, 110, 70, 83, 43, 90, 81, 72, 98, 52, 113, 87, 72, 71, 111, 80, 74, 90, 72, 108, 71, 87, 74, 70, 47, 111, 112, 77, 114, 117, 113, 100, 72, 56, 107, 51, 77, 54, 71, 73, 89, 75, 121, 108, 72, 103, 115, 56, 104, 119, 116, 111, 102, 88, 113, 56, 113, 69, 85, 120, 82, 100, 57, 67, 113, 120, 122, 67, 70, 55, 114, 83, 86, 80, 114, 113, 66, 84, 97, 49, 70, 106, 75, 47, 115, 65, 103, 122, 113, 81, 98, 103, 109, 69, 89, 76, 113, 120, 56, 84, 51, 88, 72, 57, 78, 87, 120, 116, 50, 57, 99, 109, 54, 66, 69, 111, 105, 90, 119, 87, 66, 115, 50, 68, 116, 70, 66, 108, 114, 110, 122, 51, 119, 88, 112, 66, 43, 101, 88, 54, 116, 108, 52, 52, 52, 85, 68, 87, 115, 85, 50, 48, 69, 74, 109, 78, 56, 76, 73, 102, 114, 97, 84, 73, 76, 103, 111, 55, 111, 54, 119, 75, 66, 103, 81, 68, 79, 73, 99, 83, 69, 117, 111, 57, 52, 101, 84, 98, 105, 81, 122, 107, 102, 71, 106, 51, 83, 50, 108, 77, 86, 72, 72, 69, 102, 49, 116, 90, 52, 67, 88, 100, 67, 121, 119, 78, 76, 83, 107, 74, 99, 89, 119, 118, 105, 71, 112, 105, 105, 71, 84, 75, 79, 50, 51, 75, 118, 79, 66, 66, 82, 107, 72, 114, 48, 121, 47, 110, 103, 99, 119, 55, 69, 111, 43, 51, 72, 48, 88, 105, 113, 106, 52, 111, 99, 75, 118, 80, 101, 43, 120, 79, 65, 69, 98, 111, 112, 48, 106, 43, 100, 111, 112, 98, 76, 81, 110, 80, 112, 98, 55, 109, 57, 82, 120, 85, 97, 113, 50, 108, 66, 109, 102, 88, 117, 79, 65, 71, 79, 65, 70, 80, 75, 107, 80, 55, 116, 107, 72, 85, 105, 120, 48, 89, 87, 56, 66, 104, 85, 114, 111, 88, 56, 122, 118, 73, 80, 83, 56, 69, 110, 51, 114, 113, 117, 121, 81, 75, 66, 103, 81, 67, 68, 49, 57, 81, 98, 67, 101, 68, 88, 80, 114, 111, 88, 55, 78, 66, 109, 54, 112, 50, 48, 71, 108, 70, 70, 122, 67, 85, 101, 113, 81, 101, 73, 113, 69, 70, 100, 72, 81, 118, 118, 77, 81, 53, 51, 43, 118, 122, 99, 75, 120, 54, 49, 57, 120, 68, 106, 83, 68, 78, 78, 98, 75, 106, 54, 85, 86, 77, 117, 43, 49, 114, 52, 82, 55, 43, 82, 50, 102, 75, 121, 74, 65, 99, 116, 115, 47, 75, 88, 69, 56, 53, 73, 53, 55, 89, 112, 107, 47, 119, 56, 53, 103, 122, 101, 113, 115, 116, 109, 78, 77, 104, 49, 73, 77, 81, 121, 80, 51, 82, 112, 79, 53, 122, 52, 114, 122, 75, 73, 99, 115, 55, 89, 121, 73, 110, 83, 108, 78, 109, 109, 48, 84, 110, 78, 105, 118, 114, 68, 115, 85, 90, 48, 90, 53, 112, 99, 98, 43, 110, 86, 82, 108, 112, 57, 117, 111, 106, 110, 84, 81, 75, 66, 103, 67, 105, 51, 47, 117, 119, 66, 78, 109, 111, 106, 57, 55, 87, 71, 100, 102, 103, 119, 53, 78, 109, 77, 67, 122, 70, 50, 90, 116, 112, 86, 82, 66, 82, 43, 79, 106, 76, 86, 105, 53, 99, 74, 50, 107, 89, 74, 119, 115, 85, 116, 88, 56, 49, 86, 107, 79, 107, 114, 98, 71, 73, 48, 102, 118, 83, 57, 120, 54, 119, 110, 120, 118, 113, 82, 102, 43, 57, 85, 79, 112, 112, 111, 82, 74, 47, 99, 114, 118, 109, 86, 101, 111, 115, 110, 113, 100, 104, 52, 112, 47, 43, 117, 54, 113, 89, 110, 65, 103, 97, 119, 51, 57, 106, 84, 71, 121, 118, 75, 113, 78, 54, 86, 48, 98, 115, 70, 119, 78, 69, 72, 43, 122, 97, 106, 49, 101, 109, 68, 55, 118, 102, 97, 117, 50, 106, 100, 87, 72, 107, 98, 103, 74, 76, 112, 122, 115, 110, 55, 122, 49, 69, 54, 77, 55, 79, 43, 105, 98, 52, 82, 65, 111, 71, 65, 88, 53, 111, 78, 102, 122, 106, 49, 79, 115, 54, 75, 120, 107, 118, 85, 84, 79, 79, 117, 105, 102, 83, 83, 104, 73, 98, 98, 118, 75, 116, 52, 53, 86, 110, 53, 87, 69, 72, 90, 52, 121, 70, 43, 89, 53, 103, 114, 104, 120, 87, 121, 115, 51, 114, 49, 74, 90, 65, 87, 69, 118, 71, 47, 72, 107, 102, 48, 103, 52, 49, 53, 122, 114, 115, 120, 76, 86, 47, 100, 48, 97, 72, 52, 69, 75, 76, 73, 50, 87, 84, 56, 115, 77, 102, 100, 52, 114, 111, 73, 108, 105, 79, 67, 111, 114, 71, 105, 43, 105, 116, 115, 72, 99, 79, 112, 119, 74, 48, 122, 102, 105, 100, 107, 107, 119, 102, 69, 47, 80, 110, 48, 119, 87, 56, 56, 77, 109, 109, 73, 50, 76, 89, 55, 67, 116, 113, 71, 118, 56, 66, 117, 101, 121, 97, 54, 49, 57, 49, 47, 111, 101, 53, 70, 98, 103, 71, 98, 87, 50, 77, 61}
	publicKey := []byte{77, 73, 73, 66, 73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 81, 56, 65, 77, 73, 73, 66, 67, 103, 75, 67, 65, 81, 69, 65, 115, 110, 69, 72, 100, 114, 106, 80, 119, 57, 56, 99, 108, 117, 67, 81, 116, 67, 69, 86, 112, 72, 115, 118, 65, 49, 69, 73, 113, 75, 85, 69, 85, 116, 77, 74, 86, 89, 98, 103, 50, 83, 73, 80, 51, 103, 121, 51, 47, 82, 119, 75, 87, 100, 118, 57, 100, 86, 83, 89, 50, 102, 72, 115, 81, 120, 108, 118, 119, 65, 65, 77, 106, 65, 114, 103, 113, 88, 53, 122, 109, 105, 52, 72, 90, 66, 54, 102, 72, 121, 99, 47, 68, 111, 68, 116, 51, 50, 69, 114, 102, 119, 84, 112, 98, 108, 65, 70, 88, 108, 103, 51, 118, 98, 54, 79, 71, 106, 98, 70, 121, 76, 113, 52, 110, 101, 105, 121, 51, 70, 72, 50, 106, 98, 112, 120, 105, 69, 68, 85, 115, 115, 101, 72, 83, 88, 69, 121, 75, 52, 48, 105, 118, 77, 65, 55, 71, 68, 106, 99, 73, 75, 107, 67, 54, 113, 107, 71, 75, 65, 43, 68, 116, 89, 55, 87, 69, 101, 102, 71, 78, 105, 83, 116, 99, 107, 108, 68, 77, 117, 55, 101, 81, 87, 76, 48, 106, 106, 56, 54, 80, 108, 73, 116, 90, 103, 119, 55, 106, 116, 117, 79, 117, 54, 108, 69, 119, 111, 55, 108, 83, 122, 120, 75, 112, 121, 102, 49, 105, 117, 98, 43, 72, 66, 109, 67, 78, 66, 48, 69, 76, 106, 97, 109, 114, 52, 106, 72, 106, 90, 56, 85, 53, 82, 104, 103, 110, 104, 56, 119, 72, 66, 56, 116, 89, 77, 85, 111, 106, 52, 104, 109, 97, 51, 43, 102, 50, 69, 79, 49, 71, 71, 47, 115, 119, 43, 81, 88, 116, 111, 48, 73, 85, 120, 53, 74, 109, 65, 107, 108, 115, 52, 70, 84, 65, 120, 83, 122, 77, 112, 47, 65, 98, 70, 79, 69, 76, 111, 50, 56, 53, 83, 86, 48, 52, 103, 90, 74, 48, 87, 90, 81, 97, 73, 53, 107, 113, 85, 75, 97, 103, 119, 73, 68, 65, 81, 65, 66}

	//创建json解码器解析str
	decoder := json.NewDecoder(bytes.NewReader([]byte(str)))
	//读取auth字段
	data := make(map[string]string)
	err := decoder.Decode(&data)
	if err != nil {
		//fmt.Println("Error:", err)
	}
	auth := data["auth"]
	//如果auth字段为空
	if auth == "" {
		if IsExpirationTime(str) {
			str = str
		} else {
			//get请求获取card对应的过期时间
			resp, err := http.Get("http://example.com")
			if err != nil {
				//log.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				//log.Fatal(err)
			}
			str = string(body)
		}

		//body=[]byte( "2024-09-13 21:09:21")
		//如果body不为空,则将body作为过期时间+"|"+机器码,然后进行rsa加密,作为auth字段
		if len(str) > 0 {
			if !IsExpirationTime(str) {
				return false, ""
			}
			//rsa加密
			auth, err := RsaEncryptWithPublicKey(
				string(publicKey),
				[]byte(string(str)+"&"+GetMachineCode(是否外网ip, true, true, true)),
				2)
			if err != nil {
				//fmt.Println("Error:", err)
				return false, ""
			}
			//将auth字段写入config.json文件
			data["auth"] = auth
			//创建json编码器
			jsonData, err := json.Marshal(data)
			if err != nil {
				//fmt.Println("Error:", err)
				return false, ""
			}
			return true, string(jsonData)
		}
	} else {
		//rsa解密auth字段
		str, _ := RsaDecryptWithPrivateKey(string(privateKey), auth, 2)
		//用|分割,前面是时间,后面是机器码
		arr := bytes.Split(str, []byte("&"))
		if len(arr) > 1 {
			expirationTime := string(arr[0])
			if !IsExpirationTime(expirationTime) {
				return false, ""
			}
			//机器码
			machineCode := string(arr[1])
			//判断机器码和本地机器码是否一致
			if machineCode != GetMachineCode(是否外网ip, true, true, true) {
				return false, ""
			}
			return true, ""
		}
		return false, ""
	}
	return false, ""
}

// 判断系统
func IsWindows() bool {
	os := runtime.GOOS
	if os == "windows" {
		return true
	}
	return false
}

// 判断时间是否过期
func IsExpirationTime(expirationTime string) bool {
	//2006-01-02 15:04:05 转byte[]
	fomatTime := []byte{50, 48, 48, 54, 45, 48, 49, 45, 48, 50, 32, 49, 53, 58, 48, 52, 58, 48, 53}
	timeObj, err := time.Parse(string(fomatTime), string(expirationTime))
	if err != nil {
		//fmt.Println("Error:", err)
		return false
	}
	if timeObj.Unix() < time.Now().Unix() {
		return false
	}
	return true
}

// 取机器码
func GetMachineCode(是否外网ip bool, 是否mac bool, 是否硬盘序号 bool, 是否cpuid bool) string {
	var wanIp string
	if 是否外网ip {
		resp, err := http.Get("http://myexternalip.com/raw")
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//log.Fatal(err)
		}
		wanIp = string(body)
	}
	var mac string
	if 是否mac {
		//获取mac地址
		interfaces, err := net.Interfaces()
		if err != nil {
			//log.Fatal(err)
		}
		for _, inter := range interfaces {
			tmp := inter.HardwareAddr
			if len(tmp) == 0 {
				continue
			}
			mac = tmp.String()
			break
		}
	}
	var diskSerialNumber string
	if 是否硬盘序号 {
		diskSerialNumber = ""
	}
	var cpuid string
	if 是否cpuid {
		info, err := cpu.Info()
		if err != nil {
			//fmt.Println("Error getting CPU info:", err)
		}
		for _, cpuInfo := range info {
			cpuid = cpuInfo.PhysicalID
			break
		}
	}
	machineCode := wanIp + "|" + mac + "|" + diskSerialNumber + "|" + cpuid
	return machineCode
}
