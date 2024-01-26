package MyUitls

import (
	"fmt"
	"strings"
)

//	func main() {
//		//println(GenDeviceInfo(""))
//		jsonStr :=`{"name": "John", "age": 30, "languages": ["Go", "Lua"],"a":"ad\nfadsff"}`
//
//		var data map[string]interface{}
//		err := json.Unmarshal([]byte(jsonStr), &data)
//		if err != nil {
//			fmt.Println("Error while parsing JSON:", err)
//			return
//		}
//
//		luaTable :="local table="+ convertToLuaTable(data)
//		fmt.Println(luaTable)
//	}
func convertToLuaTable(data map[string]interface{}) string {
	luaTable := "{\n"
	for key, value := range data {
		luaTable += key + ": "
		switch v := value.(type) {
		case string:
			luaTable += convertToLuaString(v)
		case float64:
			luaTable += fmt.Sprintf("%.f", v)
		case []interface{}:
			luaTable += convertArrayToLua(v)
		case map[string]interface{}:
			luaTable += convertToLuaTable(v)
		}
		luaTable += ",\n"
	}
	luaTable += "}"

	return luaTable
}

func convertArrayToLua(arr []interface{}) string {
	luaTable := "{"
	for i, item := range arr {
		switch v := item.(type) {
		case string:
			luaTable += convertToLuaString(v)
		case float64:
			luaTable += fmt.Sprintf("%.f", v)
		case []interface{}:
			luaTable += convertArrayToLua(v)
		case map[string]interface{}:
			luaTable += convertToLuaTable(v)
		}
		if i < len(arr)-1 {
			luaTable += ", "
		}
	}
	luaTable += "}"
	return luaTable
}

// 转换特殊字符为Lua字符串中的转义字符
func convertToLuaString(str string) string {
	str = strings.ReplaceAll(str, "\\", "\\\\")
	str = strings.ReplaceAll(str, "\"", "\\\"")
	str = strings.ReplaceAll(str, "'", "\\'")
	str = strings.ReplaceAll(str, "\n", "\\n")
	str = strings.ReplaceAll(str, "\r", "\\r")
	str = strings.ReplaceAll(str, "\t", "\\t")
	return fmt.Sprintf("\"%s\"", str)
}
