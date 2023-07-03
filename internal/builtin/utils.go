package builtin

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	builtinJSON "encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"hrp/internal/code"
	"hrp/internal/json"
)

// Dump2JSON 将数据转换为 Json 格式，并将其保存到指定路径的文件中
func Dump2JSON(data interface{}, path string) error {
	// 将相对路径转为绝对路径
	path, err := filepath.Abs(path)
	if err != nil {
		log.Error().Err(err).Msg("convert absolute path failed")
		return err
	}
	log.Info().Str("path", path).Msg("dump data to json")

	// init json encoder 初始化一个缓冲区 buffer 用于存储 JSON 数据
	buffer := new(bytes.Buffer)
	// 创建一个 JSON 编码器 encoder，并设置禁用转义 HTML、设置缩进
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "    ")

	err = encoder.Encode(data) // 将数据编码为 json 存储在缓冲区 buffer 中
	if err != nil {
		return err
	}

	// 将缓冲区的数据写入到指定文件中
	err = os.WriteFile(path, buffer.Bytes(), 0o644)
	if err != nil {
		log.Error().Err(err).Msg("dump json path failed")
		return err
	}
	return nil
}

// Dump2YAML 将数据转换为 Yaml 格式，并将其保存到指定路径的文件中
func Dump2YAML(data interface{}, path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		log.Error().Err(err).Msg("convert absolute path failed")
		return err
	}
	log.Info().Str("path", path).Msg("dump data to yaml")

	// init yaml encoder
	buffer := new(bytes.Buffer)
	encoder := yaml.NewEncoder(buffer)
	encoder.SetIndent(4)

	// encode
	err = encoder.Encode(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, buffer.Bytes(), 0o644)
	if err != nil {
		log.Error().Err(err).Msg("dump yaml path failed")
		return err
	}
	return nil
}

// FormatResponse 将原始响应数据中的 "body" 字段的值转换为 JSON 字符串
// 其他字段保持不变，形成一个格式化后的响应数据结构
func FormatResponse(raw interface{}) interface{} {
	formattedResponse := make(map[string]interface{})
	for key, value := range raw.(map[string]interface{}) {
		// convert value to json
		if key == "body" {
			b, _ := json.MarshalIndent(&value, "", "    ")
			value = string(b)
		}
		formattedResponse[key] = value
	}
	return formattedResponse
}

// CreateFolder 创建指定文件夹
func CreateFolder(folderPath string) error {
	log.Info().Str("path", folderPath).Msg("create folder")
	err := os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Msg("create folder failed")
		return err
	}
	return nil
}

// CreateFile 创建指定文件，并写入指定内容
func CreateFile(filePath string, data string) error {
	log.Info().Str("path", filePath).Msg("create file")
	err := os.WriteFile(filePath, []byte(data), 0o644)
	if err != nil {
		log.Error().Err(err).Msg("create file failed")
		return err
	}
	return nil
}

// IsPathExists returns true if path exists, whether path is file or dir
func IsPathExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// IsFilePathExists returns true if path exists and path is file
func IsFilePathExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// path not exists
		return false
	}

	// path exists
	if info.IsDir() {
		// path is dir, not file
		return false
	}
	return true
}

// IsFolderPathExists returns true if path exists and path is folder
func IsFolderPathExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// path not exists
		return false
	}

	// path exists and is dir
	return info.IsDir()
}

func EnsureFolderExists(folderPath string) error {
	if !IsPathExists(folderPath) {
		err := CreateFolder(folderPath)
		return err
	} else if IsFilePathExists(folderPath) {
		return fmt.Errorf("path %v should be directory", folderPath)
	}
	return nil
}

// Contains 字符串是否包含子串
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// GetRandomNumber 获取一个范围内的随机值
func GetRandomNumber(min, max int) int {
	if min > max {
		return 0
	}
	r := rand.Intn(max - min + 1)
	return min + r
}

// Interface2Float64 将接口类型转为 float64
func Interface2Float64(i interface{}) (float64, error) {
	switch v := i.(type) {
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case float32:
		return float64(v), nil
	case float64:
		return v, nil
	case string:
		intVar, err := strconv.Atoi(v)
		if err != nil {
			return 0, err
		}
		return float64(intVar), err
	}
	// json.Number
	value, ok := i.(builtinJSON.Number)
	if ok {
		return value.Float64()
	}
	return 0, errors.New("failed to convert interface to float64")
}

// TypeNormalization 将接口类型统一转为 Int 或 Uint 或 Float
func TypeNormalization(raw interface{}) interface{} {
	rawValue := reflect.ValueOf(raw)
	switch rawValue.Kind() {
	case reflect.Int:
		return rawValue.Int()
	case reflect.Int8:
		return rawValue.Int()
	case reflect.Int16:
		return rawValue.Int()
	case reflect.Int32:
		return rawValue.Int()
	case reflect.Float32:
		return rawValue.Float()
	case reflect.Uint:
		return rawValue.Uint()
	case reflect.Uint8:
		return rawValue.Uint()
	case reflect.Uint16:
		return rawValue.Uint()
	case reflect.Uint32:
		return rawValue.Uint()
	default:
		return raw
	}
}

// InterfaceType 获取接口的具体类型，并将其表示为字符串
func InterfaceType(raw interface{}) string {
	if raw == nil {
		return ""
	}
	return reflect.TypeOf(raw).String()
}

// LoadFile loads file content with file extension and assigns to structObj
// 根据文件扩展名来处理相应的数据格式，并将解析结果存储到 structObj 对象中，以便后续的操作和处理
func LoadFile(path string, structObj interface{}) (err error) {
	log.Info().Str("path", path).Msg("load file")
	file, err := ReadFile(path)
	if err != nil {
		return errors.Wrap(err, "read file failed")
	}
	// remove BOM at the beginning of file
	// 去除文件内容开头的 UTF-8 字节顺序标记 (BOM)。
	// BOM 是一个特殊的字节序列，用于指示文件的编码方式，其中 "\xef\xbb\xbf" 是 UTF-8 BOM 的字节表示形式。
	file = bytes.TrimLeft(file, "\xef\xbb\xbf")
	ext := filepath.Ext(path) // 获取文件路径 path 的扩展名
	switch ext {
	case ".json", ".har":
		// 创建一个 JSON 解码器，并将文件内容解码到 structObj 对象中
		decoder := json.NewDecoder(bytes.NewReader(file))
		decoder.UseNumber()
		err = decoder.Decode(structObj)
		if err != nil {
			err = errors.Wrap(code.LoadJSONError, err.Error())
		}
	case ".yaml", ".yml":
		// 将文件内容解析为 YAML 格式，并将解析结果存储到 structObj 对象中
		err = yaml.Unmarshal(file, structObj)
		if err != nil {
			// 将 err 错误包装为一个新的错误,增加自定义错误信息
			err = errors.Wrap(code.LoadYAMLError, err.Error())
		}
	case ".env":
		// 将文件内容解析为环境变量，并将解析结果存储到 structObj 对象中
		err = parseEnvContent(file, structObj)
		if err != nil {
			err = errors.Wrap(code.LoadEnvError, err.Error())
		}
	default:
		err = code.UnsupportedFileExtension
	}
	return err
}

// parseEnvContent 将文件内容解析为环境变量
func parseEnvContent(file []byte, obj interface{}) error {
	envMap := obj.(map[string]string)
	lines := strings.Split(string(file), "\n") // 根据换行切片
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			// empty line or comment line
			continue
		}
		var kv []string
		if strings.Contains(line, "=") {
			kv = strings.SplitN(line, "=", 2) // 按照 = 分割，最多分割两部分
		} else if strings.Contains(line, ":") {
			kv = strings.SplitN(line, ":", 2) // 按照 : 分割，最多分割两部分
		}
		if len(kv) != 2 {
			return errors.New(".env format error")
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		envMap[key] = value

		// set env
		log.Info().Str("key", key).Msg("set env")
		os.Setenv(key, value)
	}
	return nil
}

// loadFromCSV 加载 CSV 文件
func loadFromCSV(path string) []map[string]interface{} {
	log.Info().Str("path", path).Msg("load csv file")
	file, err := ReadFile(path)
	if err != nil {
		log.Error().Err(err).Msg("read csv file failed")
		os.Exit(code.GetErrorCode(err))
	}

	// 创建一个 CSV 读取器，括号内的代码将文件内容转换为字符串
	r := csv.NewReader(strings.NewReader(string(file)))
	content, err := r.ReadAll() // 读取内容赋值 并检查错误
	if err != nil {
		log.Error().Err(err).Msg("parse csv file failed")
		// 如果有错误，终止代码 且 去错误码列表内找到对应错误信息并输出
		os.Exit(code.GetErrorCode(err))
	}
	// 参数提取
	firstLine := content[0]             // parameter names 第一行为参数名
	var result []map[string]interface{} // 创建一个空切片，用于存储转换后的数据
	for i := 1; i < len(content); i++ {
		row := make(map[string]interface{}) // 创建一个空切片，用于存储当前行的数据
		for j := 0; j < len(content[i]); j++ {
			row[firstLine[j]] = content[i][j] // 将当前字段的值存储到 row 中，以参数名 firstLine[j] 作为键
		}
		result = append(result, row)
	}
	// result 切片将包含所有行的数据，每个元素都是一个 map[string]interface{}，其中键是参数名，值是对应的字段值
	return result
}

// loadMessage 根据文件路径加载文件内容
func loadMessage(path string) []byte {
	log.Info().Str("path", path).Msg("load message file")
	file, err := ReadFile(path)
	if err != nil {
		log.Error().Err(err).Msg("read message file failed")
		os.Exit(code.GetErrorCode(err))
	}
	return file
}

// ReadFile 读取文件内容
func ReadFile(path string) ([]byte, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("convert absolute path failed")
		return nil, errors.Wrap(code.LoadFileError, err.Error())
	}

	file, err := os.ReadFile(path)
	if err != nil {
		log.Error().Err(err).Msg("read file failed")
		return nil, errors.Wrap(code.LoadFileError, err.Error())
	}
	return file, nil
}

// GetFileNameWithoutExtension 获取文件名不带扩展名
func GetFileNameWithoutExtension(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return base[0 : len(base)-len(ext)]
}

// Bytes2File 将字节数组写入到指定的文件中
func Bytes2File(data []byte, filename string) error {
	// O_WRONLY 只写模式打开；TRUNC 打开文件前清空文件内容; CREATE 不存在则创建；最后的参数为八进制表示文件权限
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o755)
	defer file.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to generate file")
	}
	count, err := file.Write(data) // 将字节数组写入文件
	if err != nil {
		return err
	}
	log.Info().Msg(fmt.Sprintf("write file %s len: %d \n", filename, count))
	return nil
}

func Float32ToByte(v float32) []byte {
	bits := math.Float32bits(v)
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, bits)
	return bytes
}

func ByteToFloat32(v []byte) float32 {
	bits := binary.LittleEndian.Uint32(v)
	return math.Float32frombits(bits)
}

func Float64ToByte(v float64) []byte {
	bits := math.Float64bits(v)
	bts := make([]byte, 8)
	binary.LittleEndian.PutUint64(bts, bits)
	return bts
}

func ByteToFloat64(v []byte) float64 {
	bits := binary.LittleEndian.Uint64(v)
	return math.Float64frombits(bits)
}

func Int64ToBytes(n int64) []byte {
	bytesBuf := bytes.NewBuffer([]byte{})
	_ = binary.Write(bytesBuf, binary.BigEndian, n)
	return bytesBuf.Bytes()
}

func BytesToInt64(bys []byte) (data int64) {
	byteBuff := bytes.NewBuffer(bys)
	_ = binary.Read(byteBuff, binary.BigEndian, &data)
	return
}

// SplitInteger 将整数 m 分成 n 份，并将每份保存在一个整数切片 ints 中返回
func SplitInteger(m, n int) (ints []int) {
	quotient := m / n  // 商
	remainder := m % n // 余数
	if remainder >= 0 {
		// 如果余数大于等于 0，则分配方法为: 商的个数为 n-remainder；循环 remainder 次，每个商 + 1
		// 比如 10/3=3……1 那么商的个数是 3-1=2，由于余数是1，所以得有一次商+1也就是3+1=4，最后得到的切片为 [3 3 4]
		for i := 0; i < n-remainder; i++ {
			ints = append(ints, quotient)
		}
		for i := 0; i < remainder; i++ {
			ints = append(ints, quotient+1)
		}
		return
	} else if remainder < 0 {
		for i := 0; i < -remainder; i++ {
			ints = append(ints, quotient-1)
		}
		for i := 0; i < n+remainder; i++ {
			ints = append(ints, quotient)
		}
	}
	return
}

// sha256HMAC 接受一个密钥和消息作为参数，并返回：使用 HMAC-SHA256 算法计算得到的消息哈希值
// 这个哈希值是一个字节数组，经过格式化后以十六进制字符串的形式返回
func sha256HMAC(key []byte, data []byte) []byte {
	// 第一个参数是哈希函数的构造函数，这里使用 sha256.New 创建一个 SHA256 的哈希函数实例
	// 第二个参数是密钥，用于对消息进行加密
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return []byte(fmt.Sprintf("%x", mac.Sum(nil)))
}

// Sign 生成签名
// ver: auth-v1 or auth-v2
func Sign(ver string, ak string, sk string, body []byte) string {
	expiration := 1800 // 设置签名过期时间，单位秒
	// 创建签名密钥信息，使用 fmt.Sprintf 格式化字符串
	// 版本号 (ver）、访问密钥（ak）、当前时间戳（time.Now().Unix()）、过期时间（expiration）
	signKeyInfo := fmt.Sprintf("%s/%s/%d/%d", ver, ak, time.Now().Unix(), expiration)
	// 使用 HMAC-SHA256 算法生成签名密钥
	signKey := sha256HMAC([]byte(sk), []byte(signKeyInfo))
	signResult := sha256HMAC(signKey, body)
	// 输出签名密钥信息/签名结果
	return fmt.Sprintf("%v/%v", signKeyInfo, string(signResult))
}

// GenNameWithTimestamp 名字后面拼接上时间戳
func GenNameWithTimestamp(tmpl string) string {
	if !strings.Contains(tmpl, "%d") {
		tmpl = tmpl + "_%d"
	}
	return fmt.Sprintf(tmpl, time.Now().Unix())
}
