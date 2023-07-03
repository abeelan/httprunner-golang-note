package hrp

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"hrp/internal/builtin"
	"hrp/internal/code"
)

// ITestCase represents interface for testcases,
// includes TestCase and TestCasePath.
// 代表测试用例的接口， 被两个类实现： TestCase 和 TestCasePath
type ITestCase interface {
	GetPath() string                // 返回一个字符串，表示测试用例的路径
	ToTestCase() (*TestCase, error) // 将实现了 ITestCase 接口的类型转换为 *TestCase 类型的指针，并返回该指针
}

// TestCase is a container for one testcase, which is used for testcase runner.
// TestCase implements ITestCase interface.
// 测试用例容器，用于测试用例执行
type TestCase struct {
	Config    *TConfig
	TestSteps []IStep
}

// GetPath TestCase 实现 ITestCase 接口
func (tc *TestCase) GetPath() string {
	return tc.Config.Path
}

// ToTestCase TestCase 实现 ITestCase 接口
func (tc *TestCase) ToTestCase() (*TestCase, error) {
	return tc, nil
}

// ToTCase 将测试步骤统一转为 TCase 对象
func (tc *TestCase) ToTCase() *TCase {
	// Config
	tCase := &TCase{
		Config: tc.Config,
	}
	// TestSteps
	for _, step := range tc.TestSteps {
		if step.Type() == stepTypeTestCase {
			// 判断 step.Struct().TestCase 是否是 *TestCase 类型
			if testcase, ok := step.Struct().TestCase.(*TestCase); ok {
				// 如果是，则将其转换为 TCase 类型，为了在后续的代码中统一处理 TestCase 和 TCase 类型的对象
				step.Struct().TestCase = testcase.ToTCase()
			}
		}
		tCase.TestSteps = append(tCase.TestSteps, step.Struct())
	}
	return tCase
}

// Dump2JSON 将测试用例结构体转储到 json 文件中
func (tc *TestCase) Dump2JSON(targetPath string) error {
	tCase := tc.ToTCase()
	err := builtin.Dump2JSON(tCase, targetPath)
	if err != nil {
		return errors.Wrap(err, "dump testcase to json failed")
	}
	return nil
}

// Dump2YAML 将测试用例结构体转储到 yaml 文件中
func (tc *TestCase) Dump2YAML(targetPath string) error {
	tCase := tc.ToTCase()
	err := builtin.Dump2YAML(tCase, targetPath)
	if err != nil {
		return errors.Wrap(err, "dump testcase to yaml failed")
	}
	return nil
}

// TestCasePath implements ITestCase interface.
type TestCasePath string

func (path *TestCasePath) GetPath() string {
	return fmt.Sprintf("%v", *path)
}

// ToTestCase loads testcase path and convert to *TestCase
func (path *TestCasePath) ToTestCase() (*TestCase, error) {
	tc := &TCase{}
	casePath := path.GetPath()
	err := builtin.LoadFile(casePath, tc)
	if err != nil {
		return nil, err
	}
	return tc.ToTestCase(casePath)
}

// TCase represents testcase data structure.
// Each testcase includes one public config and several sequential teststeps.
// 测试用例数据结构，每个测试用例包括一个公共配置和几个顺序测试步骤
type TCase struct {
	Config    *TConfig `json:"config" yaml:"config"`
	TestSteps []*TStep `json:"teststeps" yaml:"teststeps"`
}

// MakeCompat converts TCase compatible with Golang engine style
func (tc *TCase) MakeCompat() (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("[MakeCompat] convert compat testcase error: %v", p)
		}
	}()
	for _, step := range tc.TestSteps {
		// 1. deal with request body compatibility 处理请求正文兼容性
		convertCompatRequestBody(step.Request)

		// 2. deal with validators compatibility 处理校验器兼容性
		err = convertCompatValidator(step.Validators)
		if err != nil {
			return err
		}

		// 3. deal with extract expr including hyphen 处理包括连字符在内的数据提取 expr
		convertExtract(step.Extract)
	}
	return nil
}

func (tc *TCase) ToTestCase(casePath string) (*TestCase, error) {
	if tc.TestSteps == nil {
		return nil, errors.Wrap(code.InvalidCaseFormat,
			"invalid testcase format, missing teststeps!")
	}

	if tc.Config == nil {
		tc.Config = &TConfig{Name: "please input testcase name"}
	}
	tc.Config.Path = casePath
	return tc.toTestCase()
}

// toTestCase converts *TCase to *TestCase
func (tc *TCase) toTestCase() (*TestCase, error) {
	testCase := &TestCase{
		Config: tc.Config,
	}

	err := tc.MakeCompat()
	if err != nil {
		return nil, err
	}

	// locate project root dir by plugin path
	projectRootDir, err := GetProjectRootDirPath(tc.Config.Path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get project root dir")
	}

	// load .env file
	dotEnvPath := filepath.Join(projectRootDir, ".env")
	if builtin.IsFilePathExists(dotEnvPath) {
		envVars := make(map[string]string)
		err = builtin.LoadFile(dotEnvPath, envVars)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load .env file")
		}

		// override testcase config env with variables loaded from .env file
		// priority: .env file > testcase config env
		if testCase.Config.Environs == nil {
			testCase.Config.Environs = make(map[string]string)
		}
		for key, value := range envVars {
			testCase.Config.Environs[key] = value
		}
	}

	for _, step := range tc.TestSteps {
		if step.API != nil {
			apiPath, ok := step.API.(string)
			if ok {
				path := filepath.Join(projectRootDir, apiPath)
				if !builtin.IsFilePathExists(path) {
					return nil, errors.Wrap(code.ReferencedFileNotFound,
						fmt.Sprintf("referenced api file not found: %s", path))
				}

				refAPI := APIPath(path)
				apiContent, err := refAPI.ToAPI()
				if err != nil {
					return nil, err
				}
				step.API = apiContent
			} else {
				apiMap, ok := step.API.(map[string]interface{})
				if !ok {
					return nil, errors.Wrap(code.InvalidCaseFormat,
						fmt.Sprintf("referenced api should be map or path(string), got %v", step.API))
				}
				api := &API{}
				err = mapstructure.Decode(apiMap, api)
				if err != nil {
					return nil, err
				}
				step.API = api
			}
			_, ok = step.API.(*API)
			if !ok {
				return nil, errors.Wrap(code.InvalidCaseFormat,
					fmt.Sprintf("failed to handle referenced API, got %v", step.TestCase))
			}
			testCase.TestSteps = append(testCase.TestSteps, &StepAPIWithOptionalArgs{
				step: step,
			})
		} else if step.TestCase != nil {
			casePath, ok := step.TestCase.(string)
			if ok {
				path := filepath.Join(projectRootDir, casePath)
				if !builtin.IsFilePathExists(path) {
					return nil, errors.Wrap(code.ReferencedFileNotFound,
						fmt.Sprintf("referenced testcase file not found: %s", path))
				}

				refTestCase := TestCasePath(path)
				tc, err := refTestCase.ToTestCase()
				if err != nil {
					return nil, err
				}
				step.TestCase = tc
			} else {
				testCaseMap, ok := step.TestCase.(map[string]interface{})
				if !ok {
					return nil, errors.Wrap(code.InvalidCaseFormat,
						fmt.Sprintf("referenced testcase should be map or path(string), got %v", step.TestCase))
				}
				tCase := &TCase{}
				err = mapstructure.Decode(testCaseMap, tCase)
				if err != nil {
					return nil, err
				}
				tc, err := tCase.toTestCase()
				if err != nil {
					return nil, err
				}
				step.TestCase = tc
			}
			_, ok = step.TestCase.(*TestCase)
			if !ok {
				return nil, errors.Wrap(code.InvalidCaseFormat,
					fmt.Sprintf("failed to handle referenced testcase, got %v", step.TestCase))
			}
			testCase.TestSteps = append(testCase.TestSteps, &StepTestCaseWithOptionalArgs{
				step: step,
			})
		} else if step.ThinkTime != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepThinkTime{
				step: step,
			})
		} else if step.Request != nil {
			// init upload
			if len(step.Request.Upload) != 0 {
				initUpload(step)
			}
			testCase.TestSteps = append(testCase.TestSteps, &StepRequestWithOptionalArgs{
				step: step,
			})
		} else if step.Transaction != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepTransaction{
				step: step,
			})
		} else if step.Rendezvous != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepRendezvous{
				step: step,
			})
		} else if step.WebSocket != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepWebSocket{
				step: step,
			})
		} else if step.IOS != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepMobile{
				step: step,
			})
		} else if step.Android != nil {
			testCase.TestSteps = append(testCase.TestSteps, &StepMobile{
				step: step,
			})
		} else {
			log.Warn().Interface("step", step).Msg("[convertTestCase] unexpected step")
		}
	}
	return testCase, nil
}

// convertCompatRequestBody 将请求体中的 data 或 json 转义到 body 上
func convertCompatRequestBody(request *Request) {
	if request != nil && request.Body == nil {
		if request.Json != nil {
			if request.Headers == nil {
				request.Headers = make(map[string]string)
			}
			request.Headers["Content-Type"] = "application/json; charset=utf-8"
			request.Body = request.Json
			request.Json = nil
		} else if request.Data != nil {
			request.Body = request.Data
			request.Data = nil
		}
	}
	// todo 逻辑优化下，更易读
	//if request == nil || request.Body != nil {
	//	return
	//}
	//
	//if request.Json != nil {
	//	request.Headers = make(map[string]string)
	//	request.Headers["Content-Type"] = "application/json; charset=utf-8"
	//	request.Body = request.Json
	//	request.Json = nil
	//} else if request.Data != nil {
	//	request.Body = request.Data
	//	request.Data = nil
	//}
}

// convertCompatValidator
func convertCompatValidator(Validators []interface{}) (err error) {
	for i, iValidator := range Validators {
		if _, ok := iValidator.(Validator); ok {
			continue
		}

		validatorMap := iValidator.(map[string]interface{})
		validator := Validator{}
		iCheck, checkExisted := validatorMap["check"]
		iAssert, assertExisted := validatorMap["assert"]
		iExpect, expectExisted := validatorMap["expect"]
		// validator check priority: Golang > Python engine style
		if checkExisted && assertExisted && expectExisted {
			// Golang engine style
			validator.Check = iCheck.(string)
			validator.Assert = iAssert.(string)
			validator.Expect = iExpect
			if iMsg, msgExisted := validatorMap["msg"]; msgExisted {
				validator.Message = iMsg.(string)
			}
			validator.Check = convertJmespathExpr(validator.Check)
			Validators[i] = validator
			continue
		}
		if len(validatorMap) == 1 {
			// Python engine style
			for assertMethod, iValidatorContent := range validatorMap {
				validatorContent := iValidatorContent.([]interface{})
				if len(validatorContent) > 3 {
					return errors.Wrap(code.InvalidCaseFormat,
						fmt.Sprintf("unexpected validator format: %v", validatorMap))
				}
				validator.Check = validatorContent[0].(string)
				validator.Assert = assertMethod
				validator.Expect = validatorContent[1]
				if len(validatorContent) == 3 {
					validator.Message = validatorContent[2].(string)
				}
			}
			validator.Check = convertJmespathExpr(validator.Check)
			Validators[i] = validator
			continue
		}
		return errors.Wrap(code.InvalidCaseFormat,
			fmt.Sprintf("unexpected validator format: %v", validatorMap))
	}
	return nil
}

// convertExtract deals with extract expr including hyphen
func convertExtract(extract map[string]string) {
	for key, value := range extract {
		extract[key] = convertJmespathExpr(value)
	}
}

// convertJmespathExpr deals with limited jmespath expression conversion
// 处理 jmespath 语法并返回
func convertJmespathExpr(checkExpr string) string {
	if strings.Contains(checkExpr, textExtractorSubRegexp) {
		return checkExpr
	}
	checkItems := strings.Split(checkExpr, ".")
	for i, checkItem := range checkItems {
		checkItem = strings.Trim(checkItem, "\"")
		lowerItem := strings.ToLower(checkItem)
		if strings.HasPrefix(lowerItem, "content-") || lowerItem == "user-agent" {
			checkItems[i] = fmt.Sprintf("\"%s\"", checkItem)
		}
	}
	return strings.Join(checkItems, ".")
}
