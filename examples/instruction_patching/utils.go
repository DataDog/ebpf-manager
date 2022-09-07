package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

func init() {
	ByteOrder = getHostByteOrder()
}

// getHostByteOrder - Returns the host byte order
func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// recoverAsset - Recover ebpf asset
func recoverAsset(asset string) io.ReaderAt {
	buf, err := Asset(asset)
	if err != nil {
		logrus.Fatal(fmt.Errorf("couldn't find asset: %w", err))
	}
	return bytes.NewReader(buf)
}
