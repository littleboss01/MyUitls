package MyUitls

import (
	"golang.org/x/sys/windows/registry"
	"log"
	"os"
	"path/filepath"
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
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()

	err = k.SetStringValue(GetSelfName(), GetSelfPath())
	if err != nil {
		log.Fatal(err)
	}
}
