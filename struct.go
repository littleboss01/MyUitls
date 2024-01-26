package MyUitls

import (
	"math/rand"
	"reflect"
	"time"
)

type Reslut struct {
	Code int
	Msg  string
}

// App 辅助结构
type App struct {
	Ip string
}

// 获取结构体字段名
func GetFieldNames(model interface{}) []string {
	v := reflect.ValueOf(model)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		//panic("not struct")
	}

	var fields []string
	for i := 0; i < v.NumField(); i++ {
		fields = append(fields, v.Type().Field(i).Name)
	}
	return fields
}

// 根据结构体随机生成数据,不是操作数据库//todo  嵌套结构体会有问题
func CreateRadomByModel(model interface{}) {
	rand.Seed(time.Now().UnixNano())

	// 使用反射函数获取 model 实参的类型和值
	v := reflect.ValueOf(model)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	// 如果参数不是结构体类型，则退出函数
	if v.Kind() != reflect.Struct {
		//panic(any("model argument must be a struct"))
	}

	// 遍历结构体的所有字段
	for i := 0; i < v.NumField(); i++ {
		fieldType := v.Type().Field(i)

		// 如果字段类型是结构体类型，则递归调用该函数生成随机值
		if fieldType.Type.Kind() == reflect.Struct {
			fieldValue := reflect.New(fieldType.Type).Elem().Interface()
			CreateRadomByModel(fieldValue)
			v.Field(i).Set(reflect.ValueOf(fieldValue))
			continue
		}

		// 生成随机值并设置到结构体字段中
		switch fieldType.Type.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			randomInt := rand.Intn(100)
			v.Field(i).SetInt(int64(randomInt))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			randomUint := rand.Uint64()
			v.Field(i).SetUint(randomUint)
		case reflect.Float32, reflect.Float64:
			randomFloat := rand.Float64()
			v.Field(i).SetFloat(randomFloat)
		case reflect.String:
			var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			randomString := make([]rune, 10)
			for i := range randomString {
				randomString[i] = letterRunes[rand.Intn(len(letterRunes))]
			}
			v.Field(i).SetString(string(randomString))
		}
	}
}
