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

var _bindataProbeO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x55\x3d\x4c\x14\x5b\x14\x3e\xb3\xfb\x80\x7d\xcb\x7b\x0f\x9e\x34\x3a\xd9\x62\x1a\x22\x44\x33\x88\x31\xc6\x10\x0b\x1a\xb5\xc1\x84\x18\x0b\x0a\x92\x71\x18\x2e\xd9\xc9\xee\xfc\x64\xee\x05\x59\xd7\x44\x2c\x4c\xb4\xb0\x34\x36\x36\xda\x59\x5a\x11\x2b\x2d\xb1\xa3\xa4\xa4\xb4\xc4\xc4\xa8\x85\x61\xcc\xb9\x7b\x67\xe6\x72\x98\x41\xad\x3d\xc9\x70\xcf\xf9\x76\xbe\x7b\xfe\x87\x07\xd7\x16\xae\xd7\x0c\x03\x32\x31\xe0\x2b\x14\x56\x21\x77\x86\x0b\x7d\x5e\xfd\xfd\x0f\x0c\xe8\x4d\xc4\xd2\xda\x36\x00\xe2\x26\x40\xc7\xfc\x9c\x66\xb6\x48\xe6\x26\x3d\xf3\x40\xda\xa7\x0d\x00\xce\x12\x07\xf5\x90\x3b\x71\xdf\xfc\x98\xe3\x71\xe4\x87\xa8\x8b\x69\x6b\xbd\x6f\xee\xe7\xf8\x1a\xb7\xda\xa8\x47\x51\xc7\xea\x9b\x7b\x39\x1e\x74\x56\x7d\xd4\x13\x6b\x6a\xa3\x6f\xee\xe6\xfe\x50\xb8\xf9\x45\xda\xef\x5e\x0e\xec\x11\x03\x60\x37\x4d\xd3\xed\x1a\xc0\x59\x00\x78\x04\x00\x98\xca\xb6\xca\xe5\x99\x3a\x91\x1f\xca\xf8\xbf\xe7\xf7\x45\x41\x10\x79\xe6\xb7\xdc\xef\xba\xf0\x03\xd4\x19\x77\xbc\xbe\xca\xab\xf0\x7b\x78\xcc\xef\x81\xf2\x3b\x76\x82\xdf\xde\xc4\x62\xee\x7f\x72\xb5\x09\xba\xbf\x50\x4c\x5b\x32\x4f\x26\xe6\xfa\x5a\x1d\xdb\x51\xd4\x41\xdd\x8a\x23\x5f\xaf\x23\xef\x71\x0f\x75\xb7\xdb\xb5\xf4\x3a\x26\x4c\xac\xcb\x7b\x42\x6b\xaa\xb4\x8e\xae\xb0\xb2\x3a\x96\xd5\xed\xfc\x09\xf1\x63\xfa\x7f\xa9\xa7\x59\x32\x37\x7f\xb2\xe0\xbc\xe0\xac\xe0\x1c\x85\x4d\xb8\xb1\xb8\x00\x70\x98\xa6\xa9\xfe\x0e\xf6\x00\xe7\x18\x67\x1d\xe7\x1c\x77\x01\xf7\x00\x77\x05\xf7\x04\x77\x28\x6e\x92\xf7\x5d\x61\x61\x4f\xb1\x9f\xd8\x73\xec\xb7\x4e\xc6\x79\xc1\x59\x42\x19\x57\x3c\xe3\xde\x2d\x68\xdc\x1f\x35\xfe\xc1\xde\xab\x27\x93\x1d\x4d\x6f\x01\xc0\x25\xcd\xde\x24\x39\xe1\xef\xb7\x35\xfb\xfd\x2f\xd6\xe2\x95\x9c\x91\x4f\x69\xd9\x6f\x75\xa8\x97\x72\xea\x72\xaa\xca\xf0\xa1\x63\xd8\x16\x00\xfc\x0f\x8d\xdc\xce\x98\x77\x25\xfe\xf7\x31\xfc\x85\xc4\x8b\x8f\x5a\x4b\xed\xf1\x4d\x00\x38\xa5\xf9\xcd\xf2\x3f\x27\xf1\x22\xce\xac\x66\x23\x12\x2f\xe2\xc9\xea\xd1\x52\x27\x5e\x5b\x03\x80\x2b\x9a\x8d\xb7\x2c\x69\xb6\xf4\x66\x0b\xb6\x29\xa0\x93\x30\x11\x27\xd1\x0a\x73\x54\xa3\x0b\x64\x26\x47\x06\x2f\x6c\xac\xf1\xc1\x4b\x0a\x98\xa1\x80\x73\x64\xfe\xb2\xb7\x8e\x82\xce\x06\x4b\xb8\x8f\x4a\xd7\xf7\x58\xc8\x19\xd8\x09\xeb\xda\xac\xed\xac\x25\x6e\xc0\x20\x70\x63\x3e\xe3\xb9\x5e\x1b\x55\x3f\xb4\x3d\xb0\xb9\x48\x84\xbb\x02\x36\xef\x05\xf2\x4c\xa2\x55\x57\xb8\x08\xcf\xda\xb3\x97\x89\x5d\xda\xbf\xdf\x91\xd7\xaa\x5e\x54\x1e\xab\x92\xef\x11\x9c\xfe\xef\x32\xd4\x33\x4c\xf0\xf9\x0a\x7f\x74\xe2\xae\xfe\x84\xbf\x43\xf0\x06\xb1\x57\x2a\xf8\x0d\x15\x28\xdd\x2f\xca\x3f\x53\xc1\xdf\x52\x7c\xba\x7f\x94\xff\x5c\x9b\xb9\x23\xf1\xd7\x06\x67\x8b\x14\x8c\xe6\xff\x41\xf1\x2f\x12\x7c\x59\x5d\x38\x46\x70\x83\x9c\x0f\x2b\xfc\x77\xea\xe5\xfe\x68\xff\x36\x2b\xf8\x71\x05\x9f\xda\x6f\x2b\xe2\xdf\x52\xfc\x65\x82\x8f\x93\x38\x9e\x6a\x3b\xac\xcb\xbe\xe2\xc7\x04\xa7\xf5\x7f\x02\xa0\x7d\x7d\x0a\x59\x52\xf3\x7b\x41\xd9\xff\x02\xc0\xa8\xc6\xcf\xe2\x78\x53\xe2\x1b\x65\x51\x25\x9a\xcd\x11\x1e\x43\x1a\x3f\xfb\xbe\xff\x08\x00\x00\xff\xff\x61\x7d\x3a\x92\xe0\x09\x00\x00")

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
		size: 2528,
		md5checksum: "",
		mode: os.FileMode(420),
		modTime: time.Unix(1642949710, 0),
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
