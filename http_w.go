package MyUitls

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	//“GET”, “POST”, “HEAD”, “PUT”, “OPTIONS”, “DELETE”, “TRACE”, “CONNECT”
	GET     = "GET"
	POST    = "POST"
	HEAD    = "HEAD"
	PUT     = "PUT"
	OPTIONS = "OPTIONS"
	DELETE  = "DELETE"
	TRACE   = "TRACE"
	CONNECT = "CONNECT"
)

type Request struct {
	Method string
	URL    string
	//Header    http.Header   //请求头 调用set会自动首字母大写,弃用
	Header    map[string][]string //请求头
	Body      string              //请求体
	Timeout   time.Duration       //超时时间
	Proxy     string              //代理
	ProxyUser string              //代理用户名
	ProxyPass string              //代理密码
	Redirect  bool                //禁止重定向

	InsecureSkipVerify bool //忽略证书
}

type Response struct {
	StatusCode int `json:"statusCode" default:"0"` //状态码
	Body       []byte
	Headers    http.Header
	Cookies    []*http.Cookie
}

func NewRequest(method string, url string) *Request {
	return &Request{
		Method: method,
		URL:    url,
		//Header: http.Header{},
		Header: make(map[string][]string),
		//Body:    body,
		Timeout: 15 * time.Second,
	}
}

func (r *Request) NewRequest() *Request {
	return &Request{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		//Body:    body,
		Timeout: r.Timeout,
	}
}

func (r *Request) NewClient() *http.Client {
	return &http.Client{}
}

// 自动处理
func (r *Request) Auto() *Request {
	//设置超时时间
	r.SetTimeout(15 * time.Second)
	//设置user-agent
	r.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36")
	//设置gzip
	r.SetHeader("Accept-Encoding", "gzip, deflate, br")
	//设置语言
	r.SetHeader("Accept-Language", "zh-CN,zh;q=0.9")
	//设置内容类型
	r.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	//设置接受
	r.SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	//设置连接
	r.SetHeader("Connection", "keep-alive")
	//设置忽略证书
	r.InsecureSkipVerify = true
	//禁止重定向
	r.Redirect = true

	return r
}

// SetHeader 添加或者修改请求头
func (r *Request) SetHeader(key, value string) *Request {
	//r.Header.Set(key, value)
	r.Header[key] = []string{value}
	return r
}

// 设置cookies
func (r *Request) SetCookies(cookie []*http.Cookie) *Request {
	var cookies = make([]string, len(cookie))
	for i, v := range cookie {
		cookies[i] = v.String()
	}
	//r.Header.Add("Cookie", strings.Join(cookies, "; "))
	r.Header["Cookie"] = []string{strings.Join(cookies, "; ")}
	return r
}

func (r *Request) SetTimeout(d time.Duration) *Request {
	r.Timeout = d
	return r
}

// SetProxy 设置代理 socks5://username:password@127.0.0.1:1080,https://127.0.0.1:8443
func (r *Request) SetProxy(address string, isProxy bool) {
	if isProxy {
		r.Proxy = address
	}
}

func (r *Request) SetRedirectPolicy(isban bool) {
	r.Redirect = isban
}

func (resp *Response) MergeCookies(req *http.Request) {
	for _, reqCookie := range req.Cookies() {
		var respCookie *http.Cookie
		// 遍历 Response 的 cookie 列表找到同名 cookie
		for _, c := range resp.Cookies {
			if c.Name == reqCookie.Name {
				respCookie = c
				break
			}
		}
		if respCookie == nil {
			// 如果 Response 中没有同名 cookie，则将 Request 的 cookie 添加到 Response 中
			resp.Cookies = append(resp.Cookies, reqCookie)
		} else {
			// 如果 Response 中有同名 cookie，则更新 value 和属性
			respCookie.Value = reqCookie.Value
			respCookie.Domain = reqCookie.Domain
			respCookie.Path = reqCookie.Path
			respCookie.Expires = reqCookie.Expires
			respCookie.RawExpires = reqCookie.RawExpires
			respCookie.MaxAge = reqCookie.MaxAge
			respCookie.Secure = reqCookie.Secure
			respCookie.HttpOnly = reqCookie.HttpOnly
			respCookie.SameSite = reqCookie.SameSite
		}
	}
}

func (r *Request) Do(client *http.Client) (*Response, error) {
	var response Response
	if client == nil {
		client = &http.Client{
			Timeout: r.Timeout,
		}
	} else {
		client.Timeout = r.Timeout
	}

	//设置禁止重定向
	if r.Redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	//golang 设置sk5代理和http代理
	var proxyUrl *url.URL
	if r.Proxy != "" {
		proxyUrl, _ = url.Parse(r.Proxy)
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: r.InsecureSkipVerify}, //忽略证书
		//TLSHandshakeTimeout: 10 * time.Second,
		Proxy: http.ProxyURL(proxyUrl), //设置代理
		//DisableCompression: true, // 禁用压缩
		//DialContext: (&net.Dialer{
		//	Timeout: 900 * time.Millisecond, // 连接超时
		//}).DialContext,
		//DialTLSContext: (&net.Dialer{
		//	Timeout: 900 * time.Millisecond, // 连接超时
		//}).DialContext,
		//DisableKeepAlives:   true,
		//ForceAttemptHTTP2:   true,
		//TLSHandshakeTimeout: 900 * time.Millisecond, // TLS 握手超时
		//		DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
		//	conn, err := net.DialTimeout(netw, addr, 2*time.Second)
		//	if err != nil {
		//		return nil, err
		//	}
		//	defer conn.Close()
		//	return conn, nil
		//},
	}

	_url, err := url.Parse(r.URL)
	if err != nil && r.URL == "" {
		return &response, err
	}
	req, err := http.NewRequest(r.Method, _url.String(), strings.NewReader(r.Body))
	if err != nil {
		return &response, err
	}
	req.Header = http.Header(r.Header)

	resp, err := client.Do(req)
	if err != nil {
		return &response, err
	}

	defer resp.Body.Close()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			//panic(err)
			return &response, err
		}
		defer reader.Close()
	default:
		reader = resp.Body
	}

	respBody, err := ioutil.ReadAll(reader)
	if err != nil {
		return &response, err
	}

	response = Response{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
		Cookies:    resp.Cookies(),
	}
	response.MergeCookies(req) //合并请求和响应的cookie到response的cookie

	return &response, nil
}

// get
func (r *Request) Get(url string) (*Response, error) {
	r.Method = "GET"
	r.URL = url
	return r.Do(nil)
}

func (r *Request) Post(url string, body string) (*Response, error) {
	r.Method = "POST"
	r.URL = url
	return r.Do(nil)
}

func (r *Request) PostJson(url, body string) (*Response, error) {
	r.Method = "POST"
	r.URL = url
	r.SetHeader("Content-Type", "application/json")
	r.Body = body
	return r.Do(nil)
}

// 上传文件
func (r *Request) UpdateFile(url, file string) (*Response, error) {
	r.Method = "POST"
	r.URL = url
	r.SetHeader("Content-Type", "multipart/form-data")
	r.Body = file
	return r.Do(nil)
}

// 下载文件
func (r *Request) DownloadFile(url string) (*Response, error) {
	r.Method = "GET"
	r.URL = url
	r.SetHeader("Content-Type", "multipart/form-data")
	return r.Do(nil)
}

// 合并请求和响应的cookie到response的cookie
func Test_http() {

	client := &http.Client{}
	cli := NewRequest("GET", "https://example.com")
	cli.SetHeader("Content-Type", "application/json")
	cli.SetHeader("Accept", "application/json")
	cli.SetCookies([]*http.Cookie{{Name: "test", Value: "test"}})
	cli.Body = `{"name":"test"}`
	cli.SetProxy("http://127.0.0.1:8888", true)
	cli.Redirect = true
	response, err := cli.Do(client)

	cli = NewRequest("GET", "https://www.baidu.com")
	cli.Auto()
	cli.SetProxy("http://127.0.0.1:8888", true)
	response, err = cli.Do(client)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		return
	}

	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		return
	}

	fmt.Println("response status code:", response.StatusCode)
	fmt.Printf("response body: %s\n", string(response.Body))

}

type PostData struct {
	//里面包含一个json对象
	maps map[string]interface{}
}

// 通过&=连接的string批量添加
func (p *PostData) AddByString(data string) {
	if p.maps == nil {
		p.maps = make(map[string]interface{})
	}
	for _, v := range strings.Split(data, "&") {
		kv := strings.Split(v, "=")
		if len(kv) == 2 {
			p.maps[kv[0]] = kv[1]
		}
	}
}

// Set 添加或设置一个键值对
func (p *PostData) Set(key, value interface{}) bool {
	if p.maps == nil {
		p.maps = make(map[string]interface{})
	}
	p.maps[key.(string)] = value
	return true
}

// Del 删除一个键值对
func (p *PostData) Del(key interface{}) bool {
	if p.maps == nil {
		return false
	}
	delete(p.maps, key.(string))
	return true
}

// Get 获取一个键值对
func (p *PostData) Get(key interface{}) interface{} {
	if p.maps == nil {
		return nil
	}
	return p.maps[key.(string)]
}

// Clear 清除所有数据
func (p *PostData) Clear() {
	p.maps = nil
}

// PostString  转换&=拼接的字符串
func (p *PostData) PostString() string {
	if p.maps == nil {
		return ""
	}
	var str string
	for k, v := range p.maps {
		//str += k + "=" + v.(string) + "&"
		str += k + "=" + fmt.Sprint(v) + "&"
	}
	return str[:len(str)-1]
}

// PostJson  转换json字符串
func (p *PostData) PostJson() string {
	if p.maps == nil {
		return ""
	}
	var jsonStr, err = json.Marshal(p.maps)
	if err != nil {
		return ""
	}
	return string(jsonStr)
}

// 转换成header格式
func (p *PostData) PostHeader() string {
	if p.maps == nil {
		return ""
	}
	var str string
	for k, v := range p.maps {
		str += k + ":" + v.(string) + "\r"
	}
	return str[:len(str)-1]
}
