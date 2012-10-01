//
// Written by Maxim Khitrov (September 2012)
//

// Package pbkdf2 provides an incremental version of the PBKDF2 key derivation
// algorithm, as described in RFC 2898.
package pbkdf2

import (
	"crypto/hmac"
	"hash"
	"runtime"
	"time"
)

type PBKDF2 struct {
	prf   hash.Hash // HMAC
	dkLen int       // Key length returned by key derivation methods
	s     []byte    // Salt value used in the first iteration
	t     []byte    // Current T values (len >= dkLen, multiple of prf.Size())
	u     []byte    // Current U values (same len as t)
	c     int       // Current iteration count
}

// New returns a new instance of PBKDF2 key derivation algorithm. Nil is
// returned if dkLen is less than one.
func New(pass, salt []byte, dkLen int, h func() hash.Hash) *PBKDF2 {
	if dkLen < 1 {
		return nil
	}
	return &PBKDF2{prf: hmac.New(h, pass), dkLen: dkLen, s: salt}
}

// NewKey derives a new key in time d (within 33%, measured as the thread's user
// time). The recommended value for d is 1 second.
func (kdf *PBKDF2) NewKey(d time.Duration) []byte {
	d = d * 2 / 3
	ch := make(chan []byte)
	kdf.Reset(nil, 0)
	go func() {
		runtime.LockOSThread()
		start := threadUtime()
		dk := kdf.Next(1024)
		for threadUtime()-start < d {
			dk = kdf.Next(kdf.Iters())
		}
		ch <- dk
	}()
	return <-ch
}

// FindKey attempts to find the key that was originally generated with NewKey.
// The iteration count, starting at 1024, is doubled until f returns true. Nil
// is returned if the key is not found in time d (within 33%, measured as the
// thread's user time).
//
// As a general rule, FindKey should be given more time than NewKey, especially
// if the operations are being performed on different computers. If NewKey was
// given 1 second, a reasonable limit for FindKey is 3 to 5 seconds.
func (kdf *PBKDF2) FindKey(d time.Duration, f func(dk []byte) bool) []byte {
	d = d * 2 / 3
	ch := make(chan []byte)
	kdf.Reset(nil, 0)
	go func() {
		runtime.LockOSThread()
		start := threadUtime()
		dk := kdf.Next(1024)
		for !f(dk) {
			if threadUtime()-start >= d {
				dk = nil
				break
			}
			dk = kdf.Next(kdf.Iters())
		}
		ch <- dk
	}()
	return <-ch
}

// Next runs the key derivation algorithm for c additional iterations and
// returns the new key.
func (kdf *PBKDF2) Next(c int) []byte {
	prf := kdf.prf
	hLen := prf.Size()
	kdf.c += c

	if kdf.t == nil {
		n := (kdf.dkLen + hLen - 1) / hLen
		t := make([]byte, 0, 2*n*hLen)
		for i := 1; i <= n; i++ {
			prf.Reset()
			prf.Write(kdf.s)
			prf.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
			t = prf.Sum(t)
		}
		kdf.t, kdf.u = t, t[len(t):cap(t)]
		copy(kdf.u, kdf.t)
		c--
	}

	t, u := kdf.t, kdf.u
	n := len(u)
	for i := 0; i < c; i++ {
		for j := 0; j < n; j += hLen {
			prf.Reset()
			prf.Write(u[j : j+hLen])
			prf.Sum(u[:j])
		}
		for j, v := range u {
			t[j] ^= v
		}
	}
	return t[:kdf.dkLen]
}

// Salt returns the current salt value.
func (kdf *PBKDF2) Salt() []byte {
	return kdf.s
}

// Size returns the number of bytes Next will return.
func (kdf *PBKDF2) Size() int {
	return kdf.dkLen
}

// Iters returns the total number of iterations performed so far.
func (kdf *PBKDF2) Iters() int {
	return kdf.c
}

// Reset returns kdf to the initial state at zero iterations. If salt is
// non-nil, the new value is used for subsequent iterations. dkLen can be
// changed by passing a new value greater than zero.
func (kdf *PBKDF2) Reset(salt []byte, dkLen int) {
	if dkLen > 0 {
		kdf.dkLen = dkLen
	}
	if salt != nil {
		kdf.s = salt
	}
	kdf.t = nil
	kdf.u = nil
	kdf.c = 0
}
