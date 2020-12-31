package jp2cc

import (
	"fmt"
	"log"
	"unsafe"
)

//#cgo LDFLAGS: -lopenjp2
//
//#include <stdlib.h>
//typedef unsigned char uint8_t;
//extern int jp2EncodeImage(void *data, size_t len, uint8_t **out, int *const out_len, int, int);
import "C"

const OPJ_CODEC_JP2 = 2

func Encode(bs []byte) ([]byte, error) {
	var datalen C.int = 0
	var out *C.uint8_t
	ret := C.jp2EncodeImage(unsafe.Pointer(&bs[0]), C.size_t(len(bs)), &out, &datalen, OPJ_CODEC_JP2, 95)
	if int(ret) < 0 {
		log.Printf("Failed to encode page\n")
		return nil, fmt.Errorf("Failed to encode page\n")
	}
	defer C.free(unsafe.Pointer(out))

	img := C.GoBytes(unsafe.Pointer(out), datalen)
	return img, nil
}
