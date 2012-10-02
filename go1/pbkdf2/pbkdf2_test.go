//
// Written by Maxim Khitrov (September 2012)
//

package pbkdf2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"testing"
	"time"
)

func TestRFC6070(t *testing.T) {
	tests := []struct {
		P, S  string
		c     []int
		dkLen int
		out   string
	}{
		{"password", "salt", []int{1}, 20,
			"0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6"},
		{"password", "salt", []int{2}, 20,
			"ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"},
		{"password", "salt", []int{1, 1}, 20,
			"ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"},
		{"password", "salt", []int{4096}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{1, 4095}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{2048, 2048}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		{"password", "salt", []int{4095, 1}, 20,
			"4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"},
		//{"password", "salt", []int{16777216}, 20,
		//	"ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", []int{4096}, 25,
			"3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38"},
		{"pass\x00word", "sa\x00lt", []int{4096}, 16,
			"56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3"},
	}
	for _, test := range tests {
		kdf := New([]byte(test.P), []byte(test.S), test.dkLen, sha1.New)
		var dk []byte
		for _, c := range test.c {
			dk = kdf.Next(c)
		}
		if out := fmt.Sprintf("% x", dk); out != test.out {
			t.Errorf("kdf.Next() expected %q; got %q", test.out, out)
		}
	}
}

func TestKeyGen(t *testing.T) {
	kdf := New([]byte("pass"), []byte("salt"), 10, sha512.New)
	key := kdf.NewKey(100 * time.Millisecond)
	itr := kdf.Iters()

	tryKey := func(dk []byte) (bool, error) {
		return bytes.Equal(dk, key), nil
	}

	kdf.Reset(nil, 0)
	dk, _ := kdf.FindKey(10*time.Millisecond, tryKey)
	if dk != nil {
		t.Errorf("kdf.FindKey(50 ms) expected nil; got % x", dk)
	}

	kdf.Reset(nil, 0)
	dk, _ = kdf.FindKey(200*time.Millisecond, tryKey)
	if !bytes.Equal(dk, key) {
		t.Errorf("kdf.FindKey(100 ms) expected % x; got % x", key, dk)
	}
	if kdf.Iters() != itr {
		t.Errorf("kdf.Iters() expected %v; got %v", itr, kdf.Iters())
	}
}
