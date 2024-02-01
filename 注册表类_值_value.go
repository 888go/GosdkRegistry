// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package 注册表类

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"syscall"
)

const (
	// NONE 注册表值类型。
	NONE                       = 0
	SZ                         = 1
	EXPAND_SZ                  = 2
	BINARY                     = 3
	DWORD                      = 4
	DWORD_BIG_ENDIAN           = 5
	LINK                       = 6
	MULTI_SZ                   = 7
	RESOURCE_LIST              = 8
	FULL_RESOURCE_DESCRIPTOR   = 9
	RESOURCE_REQUIREMENTS_LIST = 10
	QWORD                      = 11
)

var (
	// ErrShortBuffer 当缓冲区太短时返回。
	ErrShortBuffer = syscall.ERROR_MORE_DATA

	// ErrNotExist 当注册表项或值不存在时返回。
	ErrNotExist = syscall.ERROR_FILE_NOT_FOUND

	// ErrUnexpectedType 当值的类型意外时，GetValue返回。
	ErrUnexpectedType = errors.New("unexpected key value type")
)

// I取值 检索与开放注册表对象k关联的指定值的类型和数据. 它填充缓冲区buf并返回检索到的字节计数n.
// 如果buf太小，无法容纳存储的值，则返回ErrShortBuffer错误以及所需的缓冲区大小n。
// 如果没有提供缓冲区，则返回true和实际缓冲区大小n。
// 如果未提供缓冲区，则GetValue仅返回值的类型。
// 如果该值不存在，则返回的错误为ErrNotExist。
//
// I取值 是一个低级函数。如果值的类型已知，请改用相应的GetValue函数。
func (k *Key结构) I取值(名称 string, 缓冲区 []byte) (n int, 值类型 uint32, 错误 error) {
	if k == nil {
		return 0, 0, errors.New("注册表类对象为nil")
	}
	return k.Key父类.GetValue(名称, 缓冲区)
}

// I取文本值 检索与开放注册表对象k关联的指定值名称的字符串值。它还返回值的类型。
// 如果值不存在，GetStringValue将返回ErrNotExist。
// 如果值不是SZ或EXPAND_SZ，它将返回正确的值
// 类型和ErrUnexpectedType。
func (k *Key结构) I取文本值(名称 string) (值 string, 值类型 uint32, 错误 error) {
	if k == nil {
		return "", 0, errors.New("注册表类对象为nil")
	}
	return k.Key父类.GetStringValue(名称)
}

// I取文本值P 检索与开放注册表对象k关联的指定值名称的本地化字符串值。
// 如果值名称不存在或无法解析本地化字符串值, GetMUIStringValue返回ErrNotExist。
// 如果系统不支持regLoadMUIString，则GetMUIStringValue会死机；
// 在调用此函数之前，使用LoadRegLoadMUIString检查是否支持regLoadMUISString。
func (k *Key结构) I取文本值P(名称 string) (string, error) {
	if k == nil {
		return "", errors.New("注册表类对象为nil")
	}
	return k.Key父类.GetMUIStringValue(名称)
}

// I解析环境变量 展开环境变量字符串并用为当前用户定义的值替换它们。
// 使用ExpandString展开expand_SZ字符串。
func I解析环境变量(值 string) (string, error) {
	return registry.ExpandString(值)
}

// I取文本值_数组 检索与打开键k关联的指定值名称的数组字符串值。它还返回值的类型。
// 如果值不存在，GetStringsValue将返回ErrNotExist。
// 如果值不是MULTI_SZ，它将返回正确的值类型和ErrUnexpectedType。
func (k *Key结构) I取文本值_数组(名称 string) (值 []string, 值类型 uint32, 错误 error) {
	if k == nil {
		return nil, 0, errors.New("注册表类对象为nil")
	}
	return k.Key父类.GetStringsValue(名称)
}

// I取整数值64 检索与开放注册表对象k关联的指定值名称的整数值。它还返回值的类型。
// 如果值不存在，则GetIntegerValue返回ErrNotExist。
// 如果值不是DWORD或QWORD，它将返回正确的值类型和ErrUnexpectedType。
func (k *Key结构) I取整数值64(名称 string) (值 int64, 值类型 uint32, err error) {
	if k == nil {
		return 0, 0, errors.New("注册表类对象为nil")
	}
	返回整数, 值类型, err := k.Key父类.GetIntegerValue(名称)
	return int64(返回整数), 值类型, err
}

// I取字节集值 检索与开放注册表对象k关联的指定值名称的二进制值。它还返回值的类型。
// 如果值不存在，GetBinaryValue将返回ErrNotExist。
// 如果值不是BINARY，它将返回正确的值类型和ErrUnexpectedType。
func (k *Key结构) I取字节集值(名称 string) (值 []byte, 值类型 uint32, 错误 error) {
	if k == nil {
		return nil, 0, errors.New("注册表类对象为nil")
	}
	return k.Key父类.GetBinaryValue(名称)
}

func (k *Key结构) setValue(名称 string, 值类型 uint32, data []byte) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	p, err := syscall.UTF16PtrFromString(名称)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return regSetValueEx(syscall.Handle(k.Key父类), p, 0, 值类型, nil, 0)
	}
	return regSetValueEx(syscall.Handle(k.Key父类), p, 0, 值类型, &data[0], uint32(len(data)))
}

// I设置整数值32 将注册表对象k下的名称值的数据和类型设置为value和DWORD。
func (k *Key结构) I设置整数值32(名称 string, 值 int32) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}

	return k.Key父类.SetDWordValue(名称, uint32(值))
}

// I设置整数值64 将注册表对象k下的名称值的数据和类型设置为值和QWORD。
func (k *Key结构) I设置整数值64(名称 string, 值 int64) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.SetQWordValue(名称, uint64(值))
}

// I设置文本值 将注册表对象k下的名称值的数据和类型设置为值和SZ。该值不能包含零字节。
func (k *Key结构) I设置文本值(名称, 值 string) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.SetStringValue(名称, 值)
}

// I按环境变量设置文本值 将键k下的名称值的数据和类型设置为值和EXPAND_SZ。该值不能包含零字节。
func (k *Key结构) I按环境变量设置文本值(名称, 值 string) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.SetExpandStringValue(名称, 值)
}

// I设置文本值_数组 将键k下的名称值的数据和类型设置为值和MULTI_SZ。值字符串不能包含零字节。
func (k *Key结构) I设置文本值_数组(名称 string, 值 []string) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.SetStringsValue(名称, 值)
}

// I设置字节集值 将注册表对象k下的名称值的数据和类型设置为值和BINARY。
func (k *Key结构) I设置字节集值(名称 string, 值 []byte) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.SetBinaryValue(名称, 值)
}

// I删除值 从键k中删除命名值。
func (k *Key结构) I删除值(名称 string) error {
	if k == nil {
		return errors.New("注册表类对象为nil")
	}
	return k.Key父类.DeleteValue(名称)
}

// I取所有子项值 返回key k的值名称。
// 参数n控制返回名称的数量，类似于os.File.Readdirnames的工作方式。
func (k *Key结构) I取所有子项值(返回数量 int) ([]string, error) {
	if k == nil {
		return nil, errors.New("注册表类对象为nil")
	}
	return k.Key父类.ReadValueNames(返回数量)
}
