package MyUitls

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"mime/quotedprintable"
)

// CallFunc2 按次数调用函数,直到返回值在stop中,返回值为T类型和string类型
func CallFunc2[T int | bool](count int, stop []T, f interface{}, args ...interface{}) (T, string) {
	fn := reflect.ValueOf(f)
	if fn.Kind() != reflect.Func {
		panic("CallFunc: not a function")
	}
	if fn.Type().NumIn() != len(args) {
		panic("CallFunc: incorrect number of arguments")
	}

	var in []reflect.Value
	for _, arg := range args {
		in = append(in, reflect.ValueOf(arg))
	}

	var outT T
	var outS string
	for i := 0; i < count; i++ {
		out := fn.Call(in)
		if len(out) >= 2 {
			outT = out[0].Interface().(T)
			outS = out[1].Interface().(string)
		}
		for _, v := range stop {
			if outT == v {
				return outT, outS
			}
		}
	}
	return outT, outS
}

func CallerFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name()
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true // 文件或目录存在
	} else if os.IsNotExist(err) {
		return false // 文件或目录不存在
	} else {
		// 其他错误
		fmt.Println("发生其他错误")
		fmt.Println(err)
		return false
	}
}

func CreateFileWithDirectory(filePath string) error {
	dirPath := filepath.Dir(filePath)

	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return fmt.Errorf("无法创建目录: %v", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("无法创建文件: %v", err)
	}
	defer file.Close()

	fmt.Println("目录和文件已创建。")
	return nil
}

// 通用的结构体序列化
func StructToMap(obj interface{}) map[string]interface{} {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)
	var data = make(map[string]interface{})
	for i := 0; i < t.NumField(); i++ {
		data[t.Field(i).Name] = v.Field(i).Interface()
	}
	return data
}

// 使用json库,把通用的结构体转json文本
func StructToJson(obj interface{}) string {
	data, _ := json.Marshal(obj)
	return string(data)
}

// MD5加密
func Md5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// 编码utf8-ansi
func Utf8ToAnsi(str string) string {
	utf8Bytes := []byte(str)
	gbkEncoder := simplifiedchinese.GBK.NewEncoder()
	gbkBytes, _ := gbkEncoder.Bytes(utf8Bytes)
	return string(gbkBytes)
}

// 编码ansi-utf8
func AnsiToUtf8(str string) string {
	// 将字符串从 GB18030 编码转换为 UTF-8
	data, _ := ioutil.ReadAll(transform.NewReader(strings.NewReader(str), simplifiedchinese.GB18030.NewDecoder()))
	return string(data)
}

// 发送邮件
func SendMail(to, subject, body, mailtype string) error {
	host := "smtp.163.com"
	user := ""
	password := ""
	hp := strings.Split(host, ":")
	auth := smtp.PlainAuth("", user, password, hp[0])
	var content_type string
	if mailtype == "html" {
		content_type = "Content-Type: text/" + mailtype + "; charset=UTF-8"
	} else {
		content_type = "Content-Type: text/plain" + "; charset=UTF-8"

	}
	msg := []byte("To: " + to + "\r\nFrom: " + user + "\r\nSubject: " + subject + "\r\n" + content_type + "\r\n\r\n" + body)
	send_to := strings.Split(to, ";")
	err := smtp.SendMail(host, auth, user, send_to, msg)
	return err
}

// 文本文件追加内容
func AppendToFile(filename, s string) error {
	// 打开文件，如果文件不存在则创建文件，文件权限为0666
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	// 将需要追加的字符串写入文件
	_, err = io.WriteString(f, s)
	return err
}

// GetStructTag 调用方式GetStructTag(reflect.TypeOf(CardList{}), "gorm", "Comment")
func GetStructTag(structType reflect.Type, tag string, tag2 string) (map[string]interface{}, error) {
	var data = make(map[string]interface{})
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i) //获取字段的反射类型
		jsonName := field.Tag.Get("json")
		comment := field.Tag.Get("comment") //自定义tag,不是gorm的tag
		if comment != "" {
			data[jsonName] = comment
		} else {
			tt := field.Tag.Get(tag) //获取tag的值
			if tt != "" {
				values := strings.Split(tt, ";")
				for _, value := range values {
					if strings.HasPrefix(strings.ToLower(value), strings.ToLower(tag2)) {
						data[jsonName] = strings.TrimPrefix(value, tag2+":")

					}
				}
			}
		}

	}
	return data, nil
}

// 驼峰转蛇形命名
func CamelToSnake(s string) string {
	if strings.Contains(s, "_") {
		print("包含下划线")
		return s
	}
	var sb strings.Builder

	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				sb.WriteRune('_')
			}
			sb.WriteRune(unicode.ToLower(r))
		} else {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

// 获得结构体的备注json的值
func GetStructTagJson(structType reflect.Type, tag string, tag2 string) (map[string]interface{}, error) {
	var data = make(map[string]interface{})
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i) //获取字段的反射类型
		tt := field.Tag.Get(tag)     //获取tag的值
		if tt != "" {
			values := strings.Split(tt, ";")
			for _, value := range values {
				if strings.HasPrefix(strings.ToLower(value), strings.ToLower(tag2)) {
					data[field.Name] = strings.TrimPrefix(value, tag2+":")

				}
			}
		}
	}
	return data, nil
}

// 获取结构体实例指定tag和tag的值,应该传入结构体实例,而不是类型 Comment
func GetStructTagByInstance(obj interface{}, tag string, tag2 string) (map[string]string, error) {
	//判断是类型还是结构体实例
	t := reflect.TypeOf(obj) //获取类型
	//v := reflect.ValueOf(obj)//获取值
	var data = make(map[string]string)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)      //获取字段的反射类型
		tt := field.Tag.Get(tag) //获取tag的值
		//type:varchar(255);not null;comment:软件名 取出Comment:后面的软件名
		if tt != "" {
			values := strings.Split(tt, ";")
			for _, value := range values {
				if strings.HasPrefix(strings.ToLower(value), strings.ToLower(tag2)) {
					data[field.Name] = strings.TrimPrefix(value, tag2+":")

				}
			}
		}

	}
	return data, nil
}

func GetCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1)
}

// go pop3 995ssl接收邮件,使用go pop3 995ssl接收邮件
func Pop3Ssl() {
	/*// 邮件服务器地址和端口号
	server := "pop.example.com:995"
	// 用户名和密码
	username := "your_username"
	password := "your_password"

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 跳过证书验证
	}

	// 连接邮件服务器
	client, err := pop3.DialTLS(server, tlsConfig)
	if err != nil {
		panic(err)
	}
	defer client.Quit()

	// 认证用户
	if err := client.Auth(username, password); err != nil {
		panic(err)
	}

	// 获取邮件数量和大小
	num, size, err := client.Stat()
	if err != nil {
		panic(err)
	}

	// 遍历所有邮件
	for i := 1; i <= num; i++ {
		// 获取指定邮件
		mail, err := client.Retr(i)
		if err != nil {
			panic(err)
		}
		// 打印邮件内容
		fmt.Println(string(mail))
	}*/
}

//chatgpt api怎么实现上下文关联

// GetRightString 取文本指定字符串右边的字符串
func GetRightString(str string, sep string) string {
	index := strings.Index(str, sep)
	if index == -1 {
		return ""
	}
	return str[index+len(sep):]
}

// byte[]到hex string
func BytesToHexString(b []byte) string {
	var buf bytes.Buffer
	for _, v := range b {
		buf.WriteString(fmt.Sprintf("%02x", v))
	}
	return buf.String()
}

// GenerateRandomString 生成随机字符串 mode 1:数字 2:小写字母 4:大写字母 8:特殊字符
func GenerateRandomString(length int, mode int, seed int64) string {
	mrand.Seed(time.Now().UnixNano() + seed)

	var buffer []byte = make([]byte, 129)
	var str []byte = make([]byte, length)
	var bufferSize int
	if mode&1 != 0 {
		copy(buffer[bufferSize:bufferSize+10], []byte("0123456789"))
		bufferSize += 10
	}
	if mode&2 != 0 {
		copy(buffer[bufferSize:bufferSize+26], []byte("abcdefghijklmnopqrstuvwxyz"))
		bufferSize += 26
	}
	if mode&4 != 0 {
		copy(buffer[bufferSize:bufferSize+26], []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
		bufferSize += 26
	}
	if mode&8 != 0 {
		copy(buffer[bufferSize:bufferSize+33], []byte(` !"#$%&'()*+,-./:;<=>?@[\]^_`+"`{|}~"))
		bufferSize += 33
	}
	bufferSize = bufferSize - 1

	for i := 0; i < length; i++ {
		str[i] = buffer[mrand.Intn(bufferSize)]
	}

	return string(str)
}

// GenDeviceInfo 生成随机设备信息 mode 1:数字 2:小写字母 4:大写字母 8:特殊字符
func GenDeviceInfo(unqie string) (mac, imei, imsi, uuid, android, ip string) {
	var hex, numer_str string
	if unqie == "" {
		hex = Md5(time.Now().String())
	} else {
		hex = Md5(unqie)
	}

	for i, v := range hex {
		if i%2 == 0 {
			numer_str += strconv.Itoa(int(v))
		}
	}
	mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hex[0], hex[1], hex[2], hex[3], hex[4], hex[5])
	imei = fmt.Sprintf("86%s", numer_str[0:13])
	imsi = fmt.Sprintf("4600%s", numer_str[10:20])
	uuid = fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
	android = hex[0:16]
	ip = fmt.Sprintf("%d.%d.%d.%d", hex[0], hex[1], hex[2], hex[3])
	return mac, imei, imsi, uuid, android, ip
}

// 打开指定网址
func OpenUrl(url string) {
	var cmd string
	switch runtime.GOOS {
	case "windows":
		cmd = "cmd /c start " + url
	case "linux":
		cmd = "xdg-open " + url
	case "darwin":
		cmd = "open " + url
	}
	exec.Command(cmd).Start()
}

// 检测网址是否可用
func CheckUrl(url string) bool {
	resp, err := http.Get(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		return true
	}
	println(CallerFuncName(), "err:", err, "url:", url, "status:", resp.StatusCode)
	return false
}

// 域名转换成ip
func DomainToIp(domain string) string {
	/*	ips, err := net.LookupIP(domain)
		if err != nil {
			return ""
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip.String()
			}
		}
		return ""*/

	ipAddr, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		fmt.Println("域名解析失败:", err)
		return ""
	}
	ip := ipAddr.IP.String()
	return ip
}

// 监测端口是否开放
func TcpCheck(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), time.Second*2)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
func DecodeMailTitle(title string, isBase64 bool) string {
	var bytes []byte
	var regexStr = "(.*)=\\?(\\S+)\\?(\\S+)\\?(\\S+)\\?="
	re := regexp.MustCompile(regexStr)
	matchs := re.FindAllStringSubmatch(title, -1)

	for _, match := range matchs {
		if len(match) > 0 {
			//log.Println(match)
			前缀 := match[1]
			字符集 := match[2]
			编码方式 := match[3]
			内容 := match[4]
			if strings.ToLower(编码方式) == "b" {
				if isBase64 {
					return 前缀 + 内容
				}
				//base64编码
				bytes, _ = base64.StdEncoding.DecodeString(内容)
				if strings.Contains(strings.ToLower(字符集), "utf-8") {
					//return string(bytes)
				} else { //gbk解码
					decoder := simplifiedchinese.GBK.NewDecoder()
					bytes, _ = decoder.Bytes(bytes)
					//return string(bytes)
				}
			} else if strings.ToLower(编码方式) == "q" {
				//quoted-printable解码
				bytes, _ = io.ReadAll(quotedprintable.NewReader(strings.NewReader(内容)))
				//return string(bytes)
			}
			if isBase64 {
				return base64.StdEncoding.EncodeToString(bytes)
			}
			return 前缀 + string(bytes)
		}
	}

	return title
}

// 通过邮箱账号获取的gmail或者outlook的imap地址
func GetMailAddr(email string, isImap bool) (mailAddr string, serverName string, port int, isSSl bool) {
	if email == "" {
		return "", "", 0, false
	}
	if strings.Contains(email, "gmail") {
		serverName = "imap.gmail.com"
		isSSl = true
	} else if strings.Contains(email, "outlook") || strings.Contains(email, "hotmail") {
		serverName = "outlook.office365.com"
		isSSl = true
	} else if strings.Contains(email, "21cn.com") {
		serverName = "imap-ent.21cn.com"
		isSSl = true
	} else if strings.Contains(email, "pec.it") {
		serverName = "imaps.pec.aruba.it"
		isSSl = true
	} else if strings.Contains(email, "t-online.de") {
		serverName = "secureimap.t-online.de"
		isSSl = true
	} else if strings.Contains(email, "alice.it") {
		serverName = "in.alice.it"
		isSSl = false
	} else if strings.Contains(email, "sina.com") {
		serverName = "imap.sina.com"
		isSSl = false
	} else {
		//取出邮箱@右边的字符
		serverName = strings.Split(email, "@")[1]
		serverName = DomainToIp(serverName)
	}
	//如果143可以联通，则使用143端口，否则使用993端口
	if isImap {
		if isSSl == false && TcpCheck(serverName, 143) {
			port = 143
			isSSl = false
		} else {
			port = 993
			isSSl = true
		}

	} else {
		if isSSl == false && TcpCheck(serverName, 110) {
			port = 110
			isSSl = false
		} else {
			port = 995
			isSSl = true
		}
	}
	mailAddr = serverName + ":" + strconv.Itoa(port)
	return mailAddr, serverName, port, isSSl
}

// 去掉中文以外的字符
func RemoveChinese(str string) string {
	/*	var newStr strings.Builder
		for _, v := range str {
			if unicode.Is(unicode.Scripts["Han"], v)
			//|| unicode.IsLetter(v) || unicode.IsDigit(v)
			{
				newStr.WriteRune(v)
			}
		}
		return newStr.String()*/
	reg := regexp.MustCompile("[^\u4e00-\u9fa5]+")
	return reg.ReplaceAllString(str, "")
}

// 获取10位或者16位时间戳
func GetTimestamp(is16 bool) int64 {
	if is16 {
		return time.Now().UnixNano() / 1e6
	}
	return time.Now().Unix()
}

////获取设备的唯一标识
//func GetDeviceId() string {
//	//获取cpuid mac ip 硬盘序列号
//
//	//获取mac
//
//
//
//}
