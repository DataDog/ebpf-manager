package main

import (
	"encoding/binary"
	"unsafe"
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
