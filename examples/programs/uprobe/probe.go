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

var _bindataProbeO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x53\x3d\x8f\xd3\x40\x10\x7d\x9b\x84\x7c\x41\x91\x50\x81\x43\x91\x96\x02\x43\x28\x20\x15\x4a\x43\x68\x22\x84\xf8\x01\x44\x1b\x7b\x51\x2c\x62\x1b\xd9\xe6\x33\x48\x54\xf4\x34\x48\xb4\xfc\x8a\x94\xb4\xf7\x13\xae\x4c\x79\xe5\x5d\x75\xa7\x3b\xe9\x7c\x1a\xdf\x6e\x6c\x4d\x1c\xe5\x46\xda\xec\xcc\xcb\xbe\x99\x37\xb3\xeb\x9f\x2f\x27\xe3\x8a\x10\x30\x26\x70\x8a\x3c\xca\x6d\x58\xc9\xfd\x91\xfe\x6d\x43\x60\x25\x00\xb7\x0d\x7c\xb0\xce\x52\x42\xef\x09\xa0\xef\xaa\x84\x7c\xe5\x24\x6a\x69\x1d\xe7\xb8\x13\xfa\xe4\xfb\x32\x70\x97\xd6\xd1\x06\x0f\xd4\x97\x3e\xf9\x33\x19\xcf\x97\xd6\x3a\xc3\x57\x5a\x44\x6c\x9d\x67\xf1\xff\x7f\xd7\x71\x43\x00\xeb\x34\x4d\x57\x15\xa0\x07\xe0\x17\x80\x3a\x9d\xd7\xda\xfe\x30\xdd\x94\x9b\xf2\x52\x6d\xaa\x4b\xda\x48\x97\xdb\xc6\xab\x37\x13\xe0\x32\x4d\xb3\xfc\x1d\xd3\xff\xf7\xb7\x68\xfe\xb8\x2d\xee\x90\x36\xbd\x8c\xfd\x2d\x99\x0b\xb7\xe7\x00\x6a\x38\x49\xcb\xfe\xab\xa2\xba\x85\x51\xdd\x2e\x6e\x6d\xe2\x9a\xde\x1b\x19\x5e\xdf\xc2\x69\x50\x77\x0b\x79\x8c\xa6\x07\x46\x3f\x80\xec\xaa\xec\x44\x7d\x4d\x30\xfd\xac\xa2\xd8\x0b\x03\x4c\x17\x9e\xa3\x82\x58\xe1\xd3\xc7\x28\x9c\xa9\xc7\x91\x92\xee\xc2\x0b\x14\xec\x48\x2d\x6c\x35\x9f\xbe\x8f\xa4\xaf\xe0\x4b\x2f\xb0\x1d\xd8\x71\x12\x25\x72\x06\x3b\xfe\xe6\x67\x7b\x14\xba\x32\x91\x04\x0f\xec\xc1\xb3\x1b\xcc\x61\x9f\xbd\xc8\xe6\xb1\x6d\x87\xfa\xde\xdf\x31\x9c\xbf\x49\xa1\x57\x9d\xe1\xa3\x1d\xf5\x6a\x2c\xbe\xbf\x87\xcf\xef\xba\xc9\xe2\xd7\x9a\xff\x94\xe1\x6b\xbd\xf7\x18\xde\x61\x7d\x74\xb5\xcf\x67\x70\xb1\x43\x2f\xef\xbf\xb9\x83\x6f\x0e\x72\x3e\x8f\x1f\x15\xdf\x4a\x31\xaf\xe6\x3f\x29\xa9\x57\xb4\x87\x00\x5a\xbc\x36\x80\x03\xcd\x37\xfd\xb6\xf4\x5b\x36\x7c\x83\x8f\x4b\x6a\x93\x0d\x35\xff\x77\xa1\x9d\x6a\x81\x6f\xbe\xc7\xab\x00\x00\x00\xff\xff\x5b\xd8\xcc\xb3\xb8\x04\x00\x00")

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
		size: 1208,
		md5checksum: "",
		mode: os.FileMode(420),
		modTime: time.Unix(1629974278, 0),
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
