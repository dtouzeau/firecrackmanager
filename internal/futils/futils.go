package futils

import (
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func FindProgram(pname string) string {

	PossibleDirs := []string{
		"/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/bin", "/sbin", "/usr/kerberos/bin", "/usr/libexec", "/usr/lib/openldap",
	}

	for _, dir := range PossibleDirs {
		tpath := fmt.Sprintf("%v/%v", dir, pname)
		if FileExists(tpath) {
			return tpath
		}

	}
	return ""
}
func FileExists(spath string) bool {
	spath = strings.TrimSpace(spath)
	if IsLink(spath) {
		return true
	}

	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func IsLink(path string) bool {

	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}
func CreateDir(directoryPath string) {
	directoryPath = strings.TrimSpace(directoryPath)
	if directoryPath == "" {
		return
	}
	tb := strings.Split(directoryPath, "/")
	if len(tb) < 2 || !strings.Contains(directoryPath, "/") {
		for skip := 0; ; skip++ {
			pc, file, _, ok := runtime.Caller(skip)
			if !ok {
				break
			}
			funcName := runtime.FuncForPC(pc).Name()
			funcName = strings.ReplaceAll(funcName, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			file = strings.ReplaceAll(file, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
			funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")

		}

	}
	directoryPath = strings.TrimSpace(directoryPath)
	directoryPath = strings.ReplaceAll(directoryPath, `'`, "")
	directoryPath = strings.ReplaceAll(directoryPath, `"`, "")
	directoryPath = strings.TrimSpace(directoryPath)
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			return
		}
		return
	}
}
func GetCalleRuntime() string {
	if pc, file, line, ok := runtime.Caller(1); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")
		return fmt.Sprintf("%s[%s:%d]", file, funcName, line)
	}
	return ""
}
func Base64Encode(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}
func FilePutContents(filename string, data string) error {
	filename = strings.TrimSpace(filename)
	return os.WriteFile(filename, []byte(data), 0644)
}
