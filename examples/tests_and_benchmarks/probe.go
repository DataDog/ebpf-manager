// Code generated by go-bindata. DO NOT EDIT.
// sources:
// ebpf/bin/probe.o

package main


import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}


type asset struct {
	bytes []byte
	info  fileInfoEx
}

type fileInfoEx interface {
	os.FileInfo
	MD5Checksum() string
}

type bindataFileInfo struct {
	name        string
	size        int64
	mode        os.FileMode
	modTime     time.Time
	md5checksum string
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) MD5Checksum() string {
	return fi.md5checksum
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataProbeO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x55\xbd\x6f\xd3\x50\x10\xff\x39\xee\x67\x5a\x4a\xcb\x80\xaa\xa8\x95\xac\xa2\x32\x21\xd3\x46\x80\x18\x18\xaa\x22\x60\xa0\x03\xa2\x42\x62\x33\xc6\x71\x4b\xa0\x71\x2c\xdb\x85\x7e\x20\x51\x06\x24\x36\x58\x58\x51\xe1\x9f\xe8\x98\x7f\xa1\x23\x03\x43\x47\xc6\x32\xb1\x44\x3c\x74\xf6\xbd\x38\x5c\x6c\x10\x3b\x27\x25\xf7\xee\xa7\xfb\x7a\xf7\xbb\xbc\xbc\xba\xb5\x76\xbb\x62\x18\xd0\x62\xe0\x07\x72\x2b\x17\x6b\x38\x3f\xaf\xf0\xf7\x19\x18\x38\x32\x90\xfa\x7b\xb5\xae\x22\xb4\xf3\x39\xf3\x19\xad\x00\x5d\xa5\xd4\xac\x48\xf6\x06\x99\xff\x03\x4c\xa6\x36\xc5\x57\x01\x3c\xab\x7d\x55\xda\x6e\xb8\x89\xeb\xd5\xbe\xa4\x36\xc5\x07\x6d\x2b\xa1\xb3\x1f\x27\xd6\x7e\xed\x38\xab\xf3\x89\xeb\x18\xc0\xb1\x52\xea\xa8\x02\x4c\x71\xfe\x11\x00\xc3\x98\xeb\xe5\x27\x71\x2b\x43\x99\xe6\x7b\x6c\x0e\x67\x7d\x74\xd6\xd9\x36\x01\x0b\xc0\x0b\xd6\xf3\x17\xce\x8b\xfe\x4e\x7b\xfd\x5c\xb2\x36\xdb\x74\x4e\xac\xc5\xc6\x7e\xed\x5b\x0f\x6f\x06\xe1\x76\x8e\x9f\xf4\x70\x6b\xb1\x41\x29\xb1\xd1\x8e\xac\xfd\xbe\x7b\xf9\x3b\xa1\x4f\x67\x2f\xf1\x1b\xfa\x5e\xee\x10\xf7\x6b\x66\x87\xa2\x7b\x2e\xf4\xdd\x93\xf2\x28\xa5\x94\x9e\x6f\x67\x3a\xd3\x1f\xd8\xae\x00\xa0\x4c\x63\x7c\xfe\x2f\xb9\xd0\x5e\xd1\x4e\xd1\xbe\x55\x19\x23\x4e\x88\x0f\xe2\x8c\xf8\x22\x4e\x89\x4f\xe2\x9c\x74\x15\x77\xee\xad\x01\xf8\xc9\x33\xe7\x71\xc3\xd8\xbb\x8f\xb1\x97\x13\x06\x6d\xf5\x2c\x7f\xb4\x1c\x16\xfd\xa0\x84\xdc\x48\x79\xfa\xae\x24\xfe\x36\xfd\x36\x71\x28\xf0\xd7\x8c\x1f\x88\xdc\x7b\x8c\xbf\x2f\xa8\x69\xc2\x1c\xc0\x16\x01\xcc\xa4\xdb\x91\x09\xaf\x5f\xfa\xeb\x99\xc1\xf8\x00\x7e\x16\xc0\xb9\xbe\x3c\xfa\x6e\x0f\x53\xff\xfc\x91\x98\x63\xdc\x62\x9b\xcc\x71\xce\xab\xed\xd4\xdb\x4e\xfc\x9d\x04\x76\xe4\x6f\xed\x34\xc2\xcb\xad\x5d\x67\x63\x3b\xf0\x1c\xe2\x05\xce\x73\x3f\x8a\x9b\xed\x00\xce\x56\xd3\xf3\x83\xd8\x4f\xdd\x6c\xff\x89\xb3\x11\xb9\x2d\x1f\x2d\xb7\x19\xd8\x1e\xec\x38\x89\x12\xf7\x31\xec\x78\xb7\x45\xba\xe5\x86\xf1\x6f\x89\x1c\x22\x18\x76\xd4\x26\x4d\xde\xcb\xf6\xf2\x35\xac\xad\xae\x2e\x39\x57\x33\x75\x25\x53\x75\xe1\x34\x38\xc2\x7f\x96\x9b\xe9\xdc\x07\xe5\x80\x07\xfa\x51\xe0\x92\x36\x83\x3f\x23\x02\x5f\x29\xa9\x37\x24\xec\x89\xbf\xc4\xcb\xdd\x1c\x13\x7e\xa3\xcc\x9b\x94\x47\x5c\x48\xef\xff\x24\xdf\x53\xc7\x6b\x7c\x9d\xeb\xcb\x19\x9c\x70\xdd\x39\xe3\xcf\xfd\xbf\xe3\xf8\xba\xc0\xbb\xfc\x98\x4d\x09\xdc\x10\xfa\x69\x49\xfc\x34\x37\xb4\x20\x71\x11\x7f\xb1\xa4\xff\xba\x59\xdc\xaf\xe4\x6f\xbe\x24\xfe\x7a\x49\xbc\xb4\xeb\x1c\x2f\xdf\xee\x15\x8e\x5f\x12\xb8\xe4\xcf\x2e\xe1\x2f\x2c\xe0\xaf\x5a\xc0\xdf\xdd\x92\xff\x8d\x90\xeb\x9f\xb2\xad\x77\x4c\xc7\xeb\xf7\xef\x57\x00\x00\x00\xff\xff\x2a\x2e\xa2\x39\x60\x08\x00\x00")

func bindataProbeOBytes() ([]byte, error) {
	return bindataRead(
		_bindataProbeO,
		"/probe.o",
	)
}



func bindataProbeO() (*asset, error) {
	bytes, err := bindataProbeOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "/probe.o",
		size: 2144,
		md5checksum: "",
		mode: os.FileMode(420),
		modTime: time.Unix(1629886235, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}


//
// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
//
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
// nolint: deadcode
//
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

//
// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or could not be loaded.
//
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// AssetNames returns the names of the assets.
// nolint: deadcode
//
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

//
// _bindata is a table, holding each asset generator, mapped to its name.
//
var _bindata = map[string]func() (*asset, error){
	"/probe.o": bindataProbeO,
}

//
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
//
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, &os.PathError{
					Op: "open",
					Path: name,
					Err: os.ErrNotExist,
				}
			}
		}
	}
	if node.Func != nil {
		return nil, &os.PathError{
			Op: "open",
			Path: name,
			Err: os.ErrNotExist,
		}
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}


type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{Func: nil, Children: map[string]*bintree{
	"": {Func: nil, Children: map[string]*bintree{
		"probe.o": {Func: bindataProbeO, Children: map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
