package hrp

import (
	"reflect"

	"hrp/internal/builtin"
	"hrp/pkg/uixt"
)

// NewConfig returns a new constructed testcase config with specified testcase name.
func NewConfig(name string) *TConfig {
	return &TConfig{
		Name:      name,
		Environs:  make(map[string]string),
		Variables: make(map[string]interface{}),
	}
}

// TConfig represents config data structure for testcase.
// Each testcase should contain one config part.
// 测试用例的配置数据结构，每个测试用例应包含一个配置部件。
type TConfig struct {
	// json 代表序列化为 json 时的字段名
	// yaml 代表序列化为 yaml 时的字段名
	// omitempty 代表如果该字段为空值，则序列化时忽略该字段
	Name              string                 `json:"name" yaml:"name"` // required
	Verify            bool                   `json:"verify,omitempty" yaml:"verify,omitempty"`
	BaseURL           string                 `json:"base_url,omitempty" yaml:"base_url,omitempty"`   // deprecated in v4.1, moved to env
	Headers           map[string]string      `json:"headers,omitempty" yaml:"headers,omitempty"`     // public request headers
	Environs          map[string]string      `json:"environs,omitempty" yaml:"environs,omitempty"`   // environment variables
	Variables         map[string]interface{} `json:"variables,omitempty" yaml:"variables,omitempty"` // global variables
	Parameters        map[string]interface{} `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	ParametersSetting *TParamsConfig         `json:"parameters_setting,omitempty" yaml:"parameters_setting,omitempty"`
	ThinkTimeSetting  *ThinkTimeConfig       `json:"think_time,omitempty" yaml:"think_time,omitempty"`
	WebSocketSetting  *WebSocketConfig       `json:"websocket,omitempty" yaml:"websocket,omitempty"`
	IOS               []*uixt.IOSDevice      `json:"ios,omitempty" yaml:"ios,omitempty"`
	Android           []*uixt.AndroidDevice  `json:"android,omitempty" yaml:"android,omitempty"`
	RequestTimeout    float32                `json:"request_timeout,omitempty" yaml:"request_timeout,omitempty"` // request timeout in seconds
	CaseTimeout       float32                `json:"case_timeout,omitempty" yaml:"case_timeout,omitempty"`       // testcase timeout in seconds
	Export            []string               `json:"export,omitempty" yaml:"export,omitempty"`
	Weight            int                    `json:"weight,omitempty" yaml:"weight,omitempty"`
	Path              string                 `json:"path,omitempty" yaml:"path,omitempty"`     // testcase file path
	PluginSetting     *PluginConfig          `json:"plugin,omitempty" yaml:"plugin,omitempty"` // plugin config
}

// WithVariables sets variables for current testcase.
func (c *TConfig) WithVariables(variables map[string]interface{}) *TConfig {
	c.Variables = variables
	return c
}

// SetBaseURL sets base URL for current testcase.
func (c *TConfig) SetBaseURL(baseURL string) *TConfig {
	c.BaseURL = baseURL
	return c
}

// SetHeaders sets global headers for current testcase.
func (c *TConfig) SetHeaders(headers map[string]string) *TConfig {
	c.Headers = headers
	return c
}

// SetVerifySSL sets whether to verify SSL for current testcase.
func (c *TConfig) SetVerifySSL(verify bool) *TConfig {
	c.Verify = verify
	return c
}

// WithParameters sets parameters for current testcase.
func (c *TConfig) WithParameters(parameters map[string]interface{}) *TConfig {
	c.Parameters = parameters
	return c
}

// SetThinkTime sets think time config for current testcase.
func (c *TConfig) SetThinkTime(strategy thinkTimeStrategy, cfg interface{}, limit float64) *TConfig {
	c.ThinkTimeSetting = &ThinkTimeConfig{strategy, cfg, limit}
	return c
}

// SetRequestTimeout sets request timeout in seconds.
func (c *TConfig) SetRequestTimeout(seconds float32) *TConfig {
	c.RequestTimeout = seconds
	return c
}

// SetCaseTimeout sets testcase timeout in seconds.
func (c *TConfig) SetCaseTimeout(seconds float32) *TConfig {
	c.CaseTimeout = seconds
	return c
}

// ExportVars specifies variable names to export for current testcase.
// 当前测试用例导出的变量名称 多个字符串变量参数
func (c *TConfig) ExportVars(vars ...string) *TConfig {
	c.Export = vars
	return c
}

// SetWeight sets weight for current testcase, which is used in load testing.
// 设置当前测试用例的权重，用于负载测试
func (c *TConfig) SetWeight(weight int) *TConfig {
	c.Weight = weight
	return c
}

// SetWebSocket 配置 webSocket
func (c *TConfig) SetWebSocket(times, interval, timeout, size int64) *TConfig {
	c.WebSocketSetting = &WebSocketConfig{
		ReconnectionTimes:    times,
		ReconnectionInterval: interval,
		MaxMessageSize:       size,
	}
	return c
}

func (c *TConfig) SetIOS(options ...uixt.IOSDeviceOption) *TConfig {
	wdaOptions := &uixt.IOSDevice{}
	for _, option := range options {
		option(wdaOptions)
	}

	// each device can have its own settings
	if wdaOptions.UDID != "" {
		c.IOS = append(c.IOS, wdaOptions)
		return c
	}

	// device UDID is not specified, settings will be shared
	if len(c.IOS) == 0 {
		c.IOS = append(c.IOS, wdaOptions)
	} else {
		c.IOS[0] = wdaOptions
	}
	return c
}

func (c *TConfig) SetAndroid(options ...uixt.AndroidDeviceOption) *TConfig {
	uiaOptions := &uixt.AndroidDevice{}
	for _, option := range options {
		option(uiaOptions)
	}

	// each device can have its own settings
	if uiaOptions.SerialNumber != "" {
		c.Android = append(c.Android, uiaOptions)
		return c
	}

	// device UDID is not specified, settings will be shared
	if len(c.Android) == 0 {
		c.Android = append(c.Android, uiaOptions)
	} else {
		c.Android[0] = uiaOptions
	}
	return c
}

// ThinkTimeConfig 思考时间可以模拟用户在不同操作间的停顿时间，最大程度还原用户真实的操作行为
type ThinkTimeConfig struct {
	Strategy thinkTimeStrategy `json:"strategy,omitempty" yaml:"strategy,omitempty"` // default、random、multiply、ignore
	// random(map): {"min_percentage": 0.5, "max_percentage": 1.5}; 10、multiply(float64): 1.5
	Setting interface{} `json:"setting,omitempty" yaml:"setting,omitempty"`
	// limit think time no more than specific time, ignore if value <= 0
	Limit float64 `json:"limit,omitempty" yaml:"limit,omitempty"`
}

func (ttc *ThinkTimeConfig) checkThinkTime() {
	if ttc == nil {
		return
	}

	// unset strategy, set default strategy
	if ttc.Strategy == "" {
		ttc.Strategy = thinkTimeDefault
	}

	// check think time
	if ttc.Strategy == thinkTimeRandomPercentage {
		// 使用 reflect.TypeOf() 函数获取 ttc.Setting 的类型信息
		// .Kind(): 调用 Kind() 方法，返回类型的底层种类
		// != reflect.Map: 将获取到的类型的底层种类与 reflect.Map 进行比较，判断类型是否为 map 类型
		// 如果类型判断不通过，则直接给到一个默认值并退出当前函数
		if ttc.Setting == nil || reflect.TypeOf(ttc.Setting).Kind() != reflect.Map {
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		// 将 ttc.Setting 转为键为 string 的 map 类型，返回 转换后的结果 和 是否转换成功的 bool
		value, ok := ttc.Setting.(map[string]interface{})
		if !ok {
			// 如果匹配失败 则给个默认值
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		// 如果不存在 min_percentage 和 max_percentage 键，则给个默认值
		if _, ok := value["min_percentage"]; !ok {
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		if _, ok := value["max_percentage"]; !ok {
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		// 将比例转为 float64 类型，转换失败则给个默认值
		left, err := builtin.Interface2Float64(value["min_percentage"])
		if err != nil {
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		right, err := builtin.Interface2Float64(value["max_percentage"])
		if err != nil {
			ttc.Setting = thinkTimeDefaultRandom
			return
		}
		// 完成检查
		ttc.Setting = map[string]float64{"min_percentage": left, "max_percentage": right}
	} else if ttc.Strategy == thinkTimeMultiply {
		if ttc.Setting == nil {
			ttc.Setting = float64(0) // default
			return
		}
		value, err := builtin.Interface2Float64(ttc.Setting)
		if err != nil {
			ttc.Setting = float64(0) // default
			return
		}
		ttc.Setting = value
	} else if ttc.Strategy != thinkTimeIgnore {
		// unrecognized strategy, set default strategy
		ttc.Strategy = thinkTimeDefault
	}
}

type thinkTimeStrategy string

const (
	// 会保持测试用例中设置的思考时间 as recorded
	thinkTimeDefault thinkTimeStrategy = "default"
	// 测试用例中设置的思考时间在指定放缩区间中随机选值 use random percentage of recorded think time
	thinkTimeRandomPercentage thinkTimeStrategy = "random_percentage"
	// 直接设置放缩比例（设置类型为float），默认: 1 multiply recorded think time
	thinkTimeMultiply thinkTimeStrategy = "multiply"
	// 忽略测试用例中设置的思考时间 ignore recorded think time
	thinkTimeIgnore thinkTimeStrategy = "ignore"
)

const (
	thinkTimeDefaultMultiply = 1
)

// 初始化为一个包含两个键值对的 map 是 thinkTimeRandomPercentage 的默认值
var thinkTimeDefaultRandom = map[string]float64{"min_percentage": 0.5, "max_percentage": 1.5}

type PluginConfig struct {
	Path    string
	Type    string // bin、so、py
	Content []byte
}
