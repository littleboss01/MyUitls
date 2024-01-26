package MyUitls

import (
	"os"
	"path/filepath"
)

//遍历目录
func  WalkDir(root string,isHaveFile bool)(subDirs []string,err error){
	//遍历root在的域名文件夹
	err=filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 如果是目录，打印目录名称
		if info.IsDir() {
			subDirs=append(subDirs,path)
		}else if isHaveFile{
			subDirs=append(subDirs,path)
		}
		return nil
	})
	return subDirs,err
}
