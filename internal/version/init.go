package version

import (
	_ "embed"
)

/*
	embed Go 1.16 中的嵌入资源功能

	var VERSION string
	定义了一个全局变量 VERSION，类型为 string

	go:embed VERSION
	是一个特殊的注释，用于告诉编译器将 VERSION 文件的内容嵌入到可执行程序中
	VERSION 是一个文件路径，可以是相对路径或绝对路径，表示要嵌入的文件

	在运行程序时，VERSION 变量将包含指定文件的内容。可以在代码中使用该变量访问嵌入的文件内容。
*/

//go:embed VERSION
var VERSION string

// httprunner python version
const HttpRunnerMinimumVersion = "v4.3.0"
