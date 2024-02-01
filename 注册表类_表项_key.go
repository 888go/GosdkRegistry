// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

// Package 注册表类 提供对Windows注册表的访问。
//
// 下面是一个简单的示例，打开注册表项并从中读取字符串值。
//
//	k, err := gosdk_registry_cn.I打开表项(gosdk_registry_cn.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, gosdk_registry_cn.QUERY_VALUE)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer k.I关闭()
//
//	s, _, err := k.I取文本值("SystemRoot")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Windows system root is %q\n", s)
package 注册表类

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"runtime"
	"syscall"
	"time"
)

const (
	// ALL_ACCESS 注册表项安全性和'访问权限'。
	// 见 https://msdn.microsoft.com/en-us/library/windows/desktop/ms724878.aspx
	// 详细信息。

	// ALL_ACCESS 合并STANDARD_RIGHTS_REQUIRED、KEY_QUERY_VALUE、KEY_SET_VALUE、KEY_CREATE_SUB_KEY、
	//KEY_ENUMERATE_SUB_KEYS、KEY_NOTIFY和KEY_CREATE_LINK访问权限。
	ALL_ACCESS = 0xf003f

	CREATE_LINK        = 0x00020 //预留给系统使用。
	CREATE_SUB_KEY     = 0x00004 //创建注册表项的子项是必需的。
	ENUMERATE_SUB_KEYS = 0x00008 //枚举注册表项的子项所必需的。
	EXECUTE            = 0x20019 //等效于KEY_READ。
	NOTIFY             = 0x00010 //请求注册表项或注册表项子项的更改通知所必需的。
	QUERY_VALUE        = 0x00001 //查询注册表项的值所必需的。
	READ               = 0x20019 //合并STANDARD_RIGHTS_READ、KEY_QUERY_VALUE、KEY_ENUMERATE_SUB_KEYS和KEY_NOTIFY值。
	SET_VALUE          = 0x00002 //创建、删除或设置注册表值所必需的。

	// WOW64_32KEY 指示 64 位Windows上的应用程序应在 32 位注册表视图中运行。 此标志被 32 位Windows忽略。
	//有关详细信息，请参阅 访问备用注册表视图。
	//必须将此标志与此表中查询或访问注册表值的其他标志结合使用。Windows 2000：不支持此标志
	WOW64_32KEY = 0x00200 //

	// WOW64_64KEY 指示 64 位Windows上的应用程序应在 64 位注册表视图中运行。
	//此标志被 32 位Windows忽略。 有关详细信息，请参阅 访问备用注册表视图。
	//必须将此标志与此表中查询或访问注册表值的其他标志结合使用。
	//Windows 2000：不支持此标志。
	WOW64_64KEY = 0x00100

	WRITE = 0x20006 //合并STANDARD_RIGHTS_WRITE、KEY_SET_VALUE和KEY_CREATE_SUB_KEY访问权限。
)

// Key结构 是打开的Windows注册表项的句柄。
// 可以通过调用OpenKey获取注册表对象; 还有一些预定义的根注册表对象，例如CURRENT_USER。
// 注册表对象可以直接在Windows API中使用。
// type Key结构 syscall.Handle
type Key结构 struct {
	Key父类 registry.Key
}

var (
	// CLASSES_ROOT Windows定义了一些始终打开的预定义根注册表对象。
	// 应用程序可以使用这些键作为注册表的入口点。
	// 通常在OpenKey中使用这些键来打开新的键，
	//但它们也可以在需要注册表对象的任何地方使用。
	CLASSES_ROOT     = &Key结构{registry.Key(syscall.HKEY_CLASSES_ROOT)}
	CURRENT_USER     = &Key结构{registry.Key(syscall.HKEY_CURRENT_USER)}
	LOCAL_MACHINE    = &Key结构{registry.Key(syscall.HKEY_LOCAL_MACHINE)}
	USERS            = &Key结构{registry.Key(syscall.HKEY_USERS)}
	CURRENT_CONFIG   = &Key结构{registry.Key(syscall.HKEY_CURRENT_CONFIG)}
	PERFORMANCE_DATA = &Key结构{registry.Key(syscall.HKEY_PERFORMANCE_DATA)}
)

// I关闭 关闭打开键k。
func (k *Key结构) I关闭() error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.Close()
}

// I打开表项 打开一个新注册表对象，其路径名与注册表对象k相关。
// 它接受任何打开的注册表对象，
// 并返回新注册表对象和错误。
// '访问权限'参数指定要打开的注册表对象的所需'访问权限'。
func I打开表项(k *Key结构, 路径 string, 访问权限 ...uint32) (*Key结构, error) {
	var 权限参数 uint32
	if len(访问权限) > 0 {
		权限参数 = 访问权限[0]
	}

	//这里是单独增加的, 防止win64系统运行32位软件, 访问注册表被重定向到32位注册表, 具体参考精易"注册表操作Ex"类
	if 权限参数 == 0 {
		if runtime.GOARCH == "amd64" {
			权限参数 = WOW64_64KEY | ALL_ACCESS //64位注册表 注意:这里的权限 采用的是  #ALL_ACCESS  全部权限
		} else {
			权限参数 = WOW64_32KEY | ALL_ACCESS //32位注册表 注意:这里的权限 采用的是  #ALL_ACCESS  全部权限
		}
	}

	new, err := registry.OpenKey(k.Key父类, 路径, 权限参数)
	if err != nil {
		return nil, err
	}
	return &Key结构{new}, err
}

// I打开远程表项 在另一台计算机pcname上打开预定义的注册表项.要打开的注册表对象由k指定,
// 但只能是LOCAL_MACHINE、PERFORMANCE_DATA或USERS中的一个。
// 如果pcname为“”，OpenRemoteKey将返回本地计算机注册表对象。
func I打开远程表项(计算机名 string, k Key结构) (*Key结构, error) {
	new, err := registry.OpenRemoteKey(计算机名, k.Key父类)
	if err != nil {
		return nil, err
	}
	return &Key结构{new}, err
}

// I取所有子项名称 返回注册表对象k的子注册表对象的名称。
// 参数n控制返回名称的数量，
// 类似于os.File.Readdirnames的工作方式。
func (k *Key结构) I取所有子项名称(n int) ([]string, error) {
	if k == nil {
		return nil, errors.New("注册表类对象为nil")
	}
	return k.Key父类.ReadSubKeyNames(n)
}

// I创建表项 在open key k下创建一个名为路径的key。
// I创建表项 返回新注册表对象和一个布尔标志，该标志报告该注册表对象是否已存在。
//
//	参数指定要创建的注册表对象的'访问权限'。
func I创建表项(k *Key结构, 路径 string, 访问权限 ...uint32) (newk *Key结构, 是否已存在 bool, err error) {
	var 权限参数 uint32
	if len(访问权限) > 0 {
		权限参数 = 访问权限[0]
	}

	//这里是单独增加的, 防止win64系统运行32位软件, 访问注册表被重定向到32位注册表, 具体参考精易"注册表操作Ex"类
	if 权限参数 == 0 {
		if runtime.GOARCH == "amd64" {
			权限参数 = WOW64_64KEY | ALL_ACCESS //64位注册表 注意:这里的权限 采用的是  #ALL_ACCESS  全部权限
		} else {
			权限参数 = WOW64_32KEY | ALL_ACCESS //32位注册表 注意:这里的权限 采用的是  #ALL_ACCESS  全部权限
		}
	}

	new, 是否已存在, err := registry.CreateKey(k.Key父类, 路径, 权限参数)
	if err != nil {
		return nil, 是否已存在, err
	}
	return &Key结构{new}, 是否已存在, err
}

// I删除表项 删除注册表对象k的子注册表对象路径及其值。
func I删除表项(k *Key结构, 路径 string) error {
	return registry.DeleteKey(k.Key父类, 路径)
}

// A I对象信息 描述注册表对象的统计信息。由Stat.返回。
type I对象信息 struct {
	SubKeyCount     uint32
	MaxSubKeyLen    uint32 // 具有最长名称的键的子键的大小，以Unicode字符表示，不包括终止的零字节
	ValueCount      uint32
	MaxValueNameLen uint32 // 键的最长值名称的大小，以Unicode字符表示，不包括终止的零字节
	MaxValueLen     uint32 //键值中最长的数据组件，以字节为单位
	KeyInfo父类       registry.KeyInfo
}

// I取写入时间 返回键的上次写入时间。
func (ki *I对象信息) I取写入时间() time.Time {
	if ki == nil {
		return time.Time{}
	}
	return ki.KeyInfo父类.ModTime()
}

// I取对象信息 检索关于打开注册表对象k的信息。
func (k *Key结构) I取对象信息() (*I对象信息, error) {
	if k == nil {
		return nil, errors.New("注册表类对象为nil")
	}
	返回, err := k.Key父类.Stat()
	if err != nil {
		return nil, err
	}
	对象信息 := I对象信息{
		SubKeyCount:     返回.SubKeyCount,
		MaxSubKeyLen:    返回.MaxSubKeyLen, // 具有最长名称的键的子键的大小，以Unicode字符表示，不包括终止的零字节
		ValueCount:      返回.ValueCount,
		MaxValueNameLen: 返回.MaxValueNameLen, // 键的最长值名称的大小，以Unicode字符表示，不包括终止的零字节
		MaxValueLen:     返回.MaxValueLen,     //键值中最长的数据组件，以字节为单位
		KeyInfo父类:       *返回,
	}
	return &对象信息, err
}
