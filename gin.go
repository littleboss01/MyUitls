package MyUitls

import (
	"github.com/gin-gonic/gin"
	"gopkg.in/ini.v1"
	"log"
)

// gin的配置项
func GinConfig(e *gin.Engine) {
	var err error
	//读取当前目录的ini文件
	config, err := ini.Load("config.ini")
	if err != nil {
		log.Println("配置文件加载失败")
	}
	//读取配置项
	server := config.Section("server")
	mode := server.Key("mode").String()
	addr := server.Key("addr").String()
	port := server.Key("port").String()
	static := server.Key("static").String()
	//logLevel := server.Key("logLevel").String()
	if mode != "" {
		gin.SetMode(mode)
	}
	if static != "" {
		e.Static("/static", static)
	}
	if addr == "" || port == "" {
		err = e.Run()
	} else {
		err = e.Run(addr + ":" + port)
	}
	if err != nil {
		log.Println(err)
	}
}
