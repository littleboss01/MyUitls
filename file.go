package MyUitls

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// 遍历目录
func WalkDir(root string, isHaveFile bool) (subDirs []string, err error) {
	//遍历root在的域名文件夹
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 如果是目录，打印目录名称
		if info.IsDir() {
			subDirs = append(subDirs, path)
		} else if isHaveFile {
			subDirs = append(subDirs, path)
		}
		return nil
	})
	return subDirs, err
}

// 获取自身路径
func GetSelfPath() string {
	file, _ := os.Executable()
	path, _ := filepath.Abs(file)
	return path
}

// 获取路径尾部可执行文件名称
func GetSelfName() string {
	return filepath.Base(os.Args[0])
}

func AddStartup() {
	//判断系统类型
	if runtime.GOOS == "windows" {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			log.Fatal(err)
		}
		defer k.Close()

		err = k.SetStringValue(GetSelfName(), GetSelfPath())
		if err != nil {
			log.Fatal(err)
		}
	} else if runtime.GOOS == "linux" {
		serviceName := "my-service"
		serviceDescription := "My service"
		serviceUser := "root"
		executableName := GetSelfName()
		serviceFilePath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)

		// 创建服务文件
		serviceFileContent := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
User=%s
ExecStart=/usr/local/bin/%s
Restart=always

[Install]
WantedBy=multi-user.target`, serviceDescription, serviceUser, executableName)

		err := ioutil.WriteFile(serviceFilePath, []byte(serviceFileContent), 0644)
		if err != nil {
			fmt.Printf("Error creating service file: %v\n", err)
			os.Exit(1)
		}

		// 重新加载 systemd 配置
		cmd := exec.Command("systemctl", "daemon-reload")
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Error reloading systemd configuration: %v\n", err)
			os.Exit(1)
		}

		// 启用服务
		cmd = exec.Command("systemctl", "enable", fmt.Sprintf("%s.service", serviceName))
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Error enabling service: %v\n", err)
			os.Exit(1)
		}

		// 启动服务
		cmd = exec.Command("systemctl", "start", fmt.Sprintf("%s.service", serviceName))
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Error starting service: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Service created and started successfully.")

	}
}
