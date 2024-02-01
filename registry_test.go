// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package 注册表类_test

import (
	"bytes"
	"crypto/rand"
	注册表类 "e.coding.net/gogit/go/gosdk/core/win_registry_cn"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func randKeyName(prefix string) string {
	const numbers = "0123456789"
	buf := make([]byte, 10)
	rand.Read(buf)
	for i, b := range buf {
		buf[i] = numbers[b%byte(len(numbers))]
	}
	return prefix + string(buf)
}

func TestReadSubKeyNames(t *testing.T) {
	k, err := 注册表类.I打开表项(注册表类.CLASSES_ROOT, "TypeLib", 注册表类.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Fatal(err)
	}
	defer k.I关闭()

	names, err := k.I取所有子项名称(-1)
	if err != nil {
		t.Fatal(err)
	}
	var foundStdOle bool
	for _, name := range names {
		// Every PC has "stdole 2.0 OLE Automation" library installed.
		if name == "{00020430-0000-0000-C000-000000000046}" {
			foundStdOle = true
		}
	}
	if !foundStdOle {
		t.Fatal("could not find stdole 2.0 OLE Automation")
	}
}

func TestCreateOpenDeleteKey(t *testing.T) {
	k, err := 注册表类.I打开表项(注册表类.CURRENT_USER, "Software", 注册表类.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.I关闭()

	testKName := randKeyName("TestCreateOpenDeleteKey_")

	testK, exist, err := 注册表类.I创建表项(k, testKName, 注册表类.CREATE_SUB_KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer testK.I关闭()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	testKAgain, exist, err := 注册表类.I创建表项(k, testKName, 注册表类.CREATE_SUB_KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer testKAgain.I关闭()

	if !exist {
		t.Fatalf("key %q should already exist", testKName)
	}

	testKOpened, err := 注册表类.I打开表项(k, testKName, 注册表类.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Fatal(err)
	}
	defer testKOpened.I关闭()

	err = 注册表类.I删除表项(k, testKName)
	if err != nil {
		t.Fatal(err)
	}

	testKOpenedAgain, err := 注册表类.I打开表项(k, testKName, 注册表类.ENUMERATE_SUB_KEYS)
	if err == nil {
		defer testKOpenedAgain.I关闭()
		t.Fatalf("key %q should already been deleted", testKName)
	}
	if err != 注册表类.ErrNotExist {
		t.Fatalf(`unexpected error ("not exist" expected): %v`, err)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if a == nil {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type ValueTest struct {
	Type     uint32
	Name     string
	Value    interface{}
	WillFail bool
}

var ValueTests = []ValueTest{
	{Type: 注册表类.SZ, Name: "String1", Value: ""},
	{Type: 注册表类.SZ, Name: "String2", Value: "\000", WillFail: true},
	{Type: 注册表类.SZ, Name: "String3", Value: "Hello World"},
	{Type: 注册表类.SZ, Name: "String4", Value: "Hello World\000", WillFail: true},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString1", Value: ""},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString2", Value: "\000", WillFail: true},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString3", Value: "Hello World"},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString4", Value: "Hello\000World", WillFail: true},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString5", Value: "%PATH%"},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString6", Value: "%NO_SUCH_VARIABLE%"},
	{Type: 注册表类.EXPAND_SZ, Name: "ExpString7", Value: "%PATH%;."},
	{Type: 注册表类.BINARY, Name: "Binary1", Value: []byte{}},
	{Type: 注册表类.BINARY, Name: "Binary2", Value: []byte{1, 2, 3}},
	{Type: 注册表类.BINARY, Name: "Binary3", Value: []byte{3, 2, 1, 0, 1, 2, 3}},
	{Type: 注册表类.DWORD, Name: "Dword1", Value: uint64(0)},
	{Type: 注册表类.DWORD, Name: "Dword2", Value: uint64(1)},
	{Type: 注册表类.DWORD, Name: "Dword3", Value: uint64(0xff)},
	{Type: 注册表类.DWORD, Name: "Dword4", Value: uint64(0xffff)},
	{Type: 注册表类.QWORD, Name: "Qword1", Value: uint64(0)},
	{Type: 注册表类.QWORD, Name: "Qword2", Value: uint64(1)},
	{Type: 注册表类.QWORD, Name: "Qword3", Value: uint64(0xff)},
	{Type: 注册表类.QWORD, Name: "Qword4", Value: uint64(0xffff)},
	{Type: 注册表类.QWORD, Name: "Qword5", Value: uint64(0xffffff)},
	{Type: 注册表类.QWORD, Name: "Qword6", Value: uint64(0xffffffff)},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString1", Value: []string{"a", "b", "c"}},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString2", Value: []string{"abc", "", "cba"}},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString3", Value: []string{""}},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString4", Value: []string{"abcdef"}},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString5", Value: []string{"\000"}, WillFail: true},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString6", Value: []string{"a\000b"}, WillFail: true},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString7", Value: []string{"ab", "\000", "cd"}, WillFail: true},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString8", Value: []string{"\000", "cd"}, WillFail: true},
	{Type: 注册表类.MULTI_SZ, Name: "MultiString9", Value: []string{"ab", "\000"}, WillFail: true},
}

func setValues(t *testing.T, k *注册表类.Key结构) {
	for _, test := range ValueTests {
		var err error
		switch test.Type {
		case 注册表类.SZ:
			err = k.I设置文本值(test.Name, test.Value.(string))
		case 注册表类.EXPAND_SZ:
			err = k.I按环境变量设置文本值(test.Name, test.Value.(string))
		case 注册表类.MULTI_SZ:
			err = k.I设置文本值_数组(test.Name, test.Value.([]string))
		case 注册表类.BINARY:
			err = k.I设置字节集值(test.Name, test.Value.([]byte))
		case 注册表类.DWORD:
			err = k.I设置整数值32(test.Name, int32(uint32(test.Value.(uint64))))
		case 注册表类.QWORD:
			err = k.I设置整数值64(test.Name, int64(test.Value.(uint64)))
		default:
			t.Fatalf("unsupported type %d for %s value", test.Type, test.Name)
		}
		if test.WillFail {
			if err == nil {
				t.Fatalf("setting %s value %q should fail, but succeeded", test.Name, test.Value)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func enumerateValues(t *testing.T, k *注册表类.Key结构) {
	names, err := k.I取所有子项值(-1)
	if err != nil {
		t.Error(err)
		return
	}
	haveNames := make(map[string]bool)
	for _, n := range names {
		haveNames[n] = false
	}
	for _, test := range ValueTests {
		wantFound := !test.WillFail
		_, haveFound := haveNames[test.Name]
		if wantFound && !haveFound {
			t.Errorf("value %s is not found while enumerating", test.Name)
		}
		if haveFound && !wantFound {
			t.Errorf("value %s is found while enumerating, but expected to fail", test.Name)
		}
		if haveFound {
			delete(haveNames, test.Name)
		}
	}
	for n, v := range haveNames {
		t.Errorf("value %s (%v) is found while enumerating, but has not been cretaed", n, v)
	}
}

func testErrNotExist(t *testing.T, name string, err error) {
	if err == nil {
		t.Errorf("%s value should not exist", name)
		return
	}
	if err != 注册表类.ErrNotExist {
		t.Errorf("reading %s value should return 'not exist' error, but got: %s", name, err)
		return
	}
}

func testErrUnexpectedType(t *testing.T, test ValueTest, gottype uint32, err error) {
	if err == nil {
		t.Errorf("GetXValue(%q) should not succeed", test.Name)
		return
	}

	if err.Error() != 注册表类.ErrUnexpectedType.Error() {
		t.Errorf("reading %s value should return 'unexpected key value type' error, but got: %s", test.Name, err)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetStringValue(t *testing.T, k *注册表类.Key结构, test ValueTest) {
	got, gottype, err := k.I取文本值(test.Name)
	if err != nil {
		t.Errorf("I取文本值(%s) failed: %v", test.Name, err)
		return
	}
	if got != test.Value {
		t.Errorf("want %s value %q, got %q", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	if gottype == 注册表类.EXPAND_SZ {
		_, err = 注册表类.I解析环境变量(got)
		if err != nil {
			t.Errorf("I解析环境变量(%s) failed: %v", got, err)
			return
		}
	}
}

func testGetIntegerValue(t *testing.T, k *注册表类.Key结构, test ValueTest) {
	got, gottype, err := k.I取整数值64(test.Name)
	if err != nil {
		t.Errorf("I取整数值64(%s) failed: %v", test.Name, err)
		return
	}
	if got != int64(test.Value.(uint64)) {
		t.Errorf("want %s value %v, got %v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetBinaryValue(t *testing.T, k *注册表类.Key结构, test ValueTest) {
	got, gottype, err := k.I取字节集值(test.Name)
	if err != nil {
		t.Errorf("I取字节集值(%s) failed: %v", test.Name, err)
		return
	}
	if !bytes.Equal(got, test.Value.([]byte)) {
		t.Errorf("want %s value %v, got %v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetStringsValue(t *testing.T, k *注册表类.Key结构, test ValueTest) {
	got, gottype, err := k.I取文本值_数组(test.Name)
	if err != nil {
		t.Errorf("I取文本值_数组(%s) failed: %v", test.Name, err)
		return
	}
	if !equalStringSlice(got, test.Value.([]string)) {
		t.Errorf("want %s value %#v, got %#v", test.Name, test.Value, got)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
}

func testGetValue(t *testing.T, k *注册表类.Key结构, test ValueTest, size int) {
	if size <= 0 {
		return
	}
	// read data with no buffer
	gotsize, gottype, err := k.I取值(test.Name, nil)
	if err != nil {
		t.Errorf("I取值(%s, [%d]byte) failed: %v", test.Name, size, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// read data with short buffer
	gotsize, gottype, err = k.I取值(test.Name, make([]byte, size-1))
	if err == nil {
		t.Errorf("I取值(%s, [%d]byte) should fail, but succeeded", test.Name, size-1)
		return
	}
	if err != 注册表类.ErrShortBuffer {
		t.Errorf("reading %s value should return 'short buffer' error, but got: %s", test.Name, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// read full data
	gotsize, gottype, err = k.I取值(test.Name, make([]byte, size))
	if err != nil {
		t.Errorf("I取值(%s, [%d]byte) failed: %v", test.Name, size, err)
		return
	}
	if gotsize != size {
		t.Errorf("want %s value size of %d, got %v", test.Name, size, gotsize)
		return
	}
	if gottype != test.Type {
		t.Errorf("want %s value type %v, got %v", test.Name, test.Type, gottype)
		return
	}
	// check I取值 returns ErrNotExist as required
	_, _, err = k.I取值(test.Name+"_not_there", make([]byte, size))
	if err == nil {
		t.Errorf("I取值(%q) should not succeed", test.Name)
		return
	}
	if err != 注册表类.ErrNotExist {
		t.Errorf("I取值(%q) should return 'not exist' error, but got: %s", test.Name, err)
		return
	}
}

func testValues(t *testing.T, k *注册表类.Key结构) {
	for _, test := range ValueTests {
		switch test.Type {
		case 注册表类.SZ, 注册表类.EXPAND_SZ:
			if test.WillFail {
				_, _, err := k.I取文本值(test.Name)
				testErrNotExist(t, test.Name, err)
			} else {
				testGetStringValue(t, k, test)
				_, gottype, err := k.I取整数值64(test.Name)
				testErrUnexpectedType(t, test, gottype, err)
				// utf16字符串的字节大小不理想，
				// 但对于当前测试值是正确的。
				// 大小还包括终止0。
				testGetValue(t, k, test, (len(test.Value.(string))+1)*2)
			}
			_, _, err := k.I取文本值(test.Name + "_string_not_created")
			testErrNotExist(t, test.Name+"_string_not_created", err)
		case 注册表类.DWORD, 注册表类.QWORD:
			testGetIntegerValue(t, k, test)
			_, gottype, err := k.I取字节集值(test.Name)
			testErrUnexpectedType(t, test, gottype, err)
			_, _, err = k.I取整数值64(test.Name + "_int_not_created")
			testErrNotExist(t, test.Name+"_int_not_created", err)
			size := 8
			if test.Type == 注册表类.DWORD {
				size = 4
			}
			testGetValue(t, k, test, size)
		case 注册表类.BINARY:
			testGetBinaryValue(t, k, test)
			_, gottype, err := k.I取文本值_数组(test.Name)
			testErrUnexpectedType(t, test, gottype, err)
			_, _, err = k.I取字节集值(test.Name + "_byte_not_created")
			testErrNotExist(t, test.Name+"_byte_not_created", err)
			testGetValue(t, k, test, len(test.Value.([]byte)))
		case 注册表类.MULTI_SZ:
			if test.WillFail {
				_, _, err := k.I取文本值_数组(test.Name)
				testErrNotExist(t, test.Name, err)
			} else {
				testGetStringsValue(t, k, test)
				_, gottype, err := k.I取文本值(test.Name)
				testErrUnexpectedType(t, test, gottype, err)
				size := 0
				for _, s := range test.Value.([]string) {
					size += len(s) + 1 // nil terminated
				}
				size += 1 // extra nil at the end
				size *= 2 // count bytes, not uint16
				testGetValue(t, k, test, size)
			}
			_, _, err := k.I取文本值_数组(test.Name + "_strings_not_created")
			testErrNotExist(t, test.Name+"_strings_not_created", err)
		default:
			t.Errorf("unsupported type %d for %s value", test.Type, test.Name)
			continue
		}
	}
}

func testStat(t *testing.T, k *注册表类.Key结构) {
	subk, _, err := 注册表类.I创建表项(k, "subkey", 注册表类.CREATE_SUB_KEY)
	if err != nil {
		t.Error(err)
		return
	}
	defer subk.I关闭()

	defer 注册表类.I删除表项(k, "subkey")

	ki, err := k.I取对象信息()
	if err != nil {
		t.Error(err)
		return
	}
	if ki.SubKeyCount != 1 {
		t.Error("key must have 1 subkey")
	}
	if ki.MaxSubKeyLen != 6 {
		t.Error("key max subkey name length must be 6")
	}
	if ki.ValueCount != 24 {
		t.Errorf("key must have 24 values, but is %d", ki.ValueCount)
	}
	if ki.MaxValueNameLen != 12 {
		t.Errorf("key max value name length must be 10, but is %d", ki.MaxValueNameLen)
	}
	if ki.MaxValueLen != 38 {
		t.Errorf("key max value length must be 38, but is %d", ki.MaxValueLen)
	}
	if mt, ct := ki.I取写入时间(), time.Now(); ct.Sub(mt) > 100*time.Millisecond {
		t.Errorf("键模式时间不接近当前时间：mtime=%v current=%v delta=%v", mt, ct, ct.Sub(mt))
	}
}

func deleteValues(t *testing.T, k *注册表类.Key结构) {
	for _, test := range ValueTests {
		if test.WillFail {
			continue
		}
		err := k.I删除值(test.Name)
		if err != nil {
			t.Error(err)
			continue
		}
	}
	names, err := k.I取所有子项值(-1)
	if err != nil {
		t.Error(err)
		return
	}
	if len(names) != 0 {
		t.Errorf("删除后仍保留一些值：%v", names)
	}
}

func TestValues(t *testing.T) {
	softwareK, err := 注册表类.I打开表项(注册表类.CURRENT_USER, "Software", 注册表类.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer softwareK.I关闭()

	testKName := randKeyName("TestValues_")

	k, exist, err := 注册表类.I创建表项(softwareK, testKName, 注册表类.CREATE_SUB_KEY|注册表类.QUERY_VALUE|注册表类.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.I关闭()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	defer 注册表类.I删除表项(softwareK, testKName)

	setValues(t, k)

	enumerateValues(t, k)

	testValues(t, k)

	testStat(t, k)

	deleteValues(t, k)
}

func TestExpandString(t *testing.T) {
	got, err := 注册表类.I解析环境变量("%PATH%")
	if err != nil {
		t.Fatal(err)
	}
	want := os.Getenv("PATH")
	if got != want {
		t.Errorf("want %q string expanded, got %q", want, got)
	}
}

func TestInvalidValues(t *testing.T) {
	softwareK, err := 注册表类.I打开表项(注册表类.CURRENT_USER, "Software", 注册表类.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer softwareK.I关闭()

	testKName := randKeyName("TestInvalidValues_")

	k, exist, err := 注册表类.I创建表项(softwareK, testKName, 注册表类.CREATE_SUB_KEY|注册表类.QUERY_VALUE|注册表类.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.I关闭()

	if exist {
		t.Fatalf("key %q already exists", testKName)
	}

	defer 注册表类.I删除表项(softwareK, testKName)

	var tests = []struct {
		Type uint32
		Name string
		Data []byte
	}{
		{注册表类.DWORD, "Dword1", nil},
		{注册表类.DWORD, "Dword2", []byte{1, 2, 3}},
		{注册表类.QWORD, "Qword1", nil},
		{注册表类.QWORD, "Qword2", []byte{1, 2, 3}},
		{注册表类.QWORD, "Qword3", []byte{1, 2, 3, 4, 5, 6, 7}},
		{注册表类.MULTI_SZ, "MultiString1", nil},
		{注册表类.MULTI_SZ, "MultiString2", []byte{0}},
		{注册表类.MULTI_SZ, "MultiString3", []byte{'a', 'b', 0}},
		{注册表类.MULTI_SZ, "MultiString4", []byte{'a', 0, 0, 'b', 0}},
		{注册表类.MULTI_SZ, "MultiString5", []byte{'a', 0, 0}},
	}

	for _, test := range tests {
		err := k.SetValue(test.Name, test.Type, test.Data)
		if err != nil {
			t.Fatalf("SetValue for %q failed: %v", test.Name, err)
		}
	}

	for _, test := range tests {
		switch test.Type {
		case 注册表类.DWORD, 注册表类.QWORD:
			value, valType, err := k.I取整数值64(test.Name)
			if err == nil {
				t.Errorf("I取整数值64(%q) succeeded. Returns type=%d value=%v", test.Name, valType, value)
			}
		case 注册表类.MULTI_SZ:
			value, valType, err := k.I取文本值_数组(test.Name)
			if err == nil {
				if len(value) != 0 {
					t.Errorf("I取文本值_数组(%q) succeeded. Returns type=%d value=%v", test.Name, valType, value)
				}
			}
		default:
			t.Errorf("unsupported type %d for %s value", test.Type, test.Name)
		}
	}
}

func TestGetMUIStringValue(t *testing.T) {
	if err := 注册表类.LoadRegLoadMUIString(); err != nil {
		t.Skip("regLoadMUIString not supported; skipping")
	}
	if err := procGetDynamicTimeZoneInformation.Find(); err != nil {
		t.Skipf("%s not supported; skipping", procGetDynamicTimeZoneInformation.Name)
	}
	var dtzi DynamicTimezoneinformation
	if _, err := GetDynamicTimeZoneInformation(&dtzi); err != nil {
		t.Fatal(err)
	}
	tzKeyName := syscall.UTF16ToString(dtzi.TimeZoneKeyName[:])
	timezoneK, err := 注册表类.I打开表项(注册表类.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\`+tzKeyName, 注册表类.READ)
	if err != nil {
		t.Fatal(err)
	}
	defer timezoneK.I关闭()

	type testType struct {
		name string
		want string
	}
	var tests = []testType{
		{"MUI_Std", syscall.UTF16ToString(dtzi.StandardName[:])},
	}
	if dtzi.DynamicDaylightTimeDisabled == 0 {
		tests = append(tests, testType{"MUI_Dlt", syscall.UTF16ToString(dtzi.DaylightName[:])})
	}

	for _, test := range tests {
		got, err := timezoneK.I取文本值P(test.name)
		if err != nil {
			t.Error("I取文本值P:", err)
		}

		if got != test.want {
			t.Errorf("I取文本值P: %s: Got %q, want %q", test.name, got, test.want)
		}
	}
}

type DynamicTimezoneinformation struct {
	Bias                        int32
	StandardName                [32]uint16
	StandardDate                syscall.Systemtime
	StandardBias                int32
	DaylightName                [32]uint16
	DaylightDate                syscall.Systemtime
	DaylightBias                int32
	TimeZoneKeyName             [128]uint16
	DynamicDaylightTimeDisabled uint8
}

var (
	kernel32DLL = syscall.NewLazyDLL("kernel32")

	procGetDynamicTimeZoneInformation = kernel32DLL.NewProc("GetDynamicTimeZoneInformation")
)

func GetDynamicTimeZoneInformation(dtzi *DynamicTimezoneinformation) (rc uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetDynamicTimeZoneInformation.Addr(), 1, uintptr(unsafe.Pointer(dtzi)), 0, 0)
	rc = uint32(r0)
	if rc == 0xffffffff {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
