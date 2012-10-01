//
// Written by Maxim Khitrov (September 2012)
//

// +build !windows

package pbkdf2

import (
	"syscall"
	"time"
)

func threadUtime() time.Duration {
	var u syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_THREAD, &u); err != nil {
		panic(err)
	}
	return time.Duration(syscall.TimevalToNsec(u.Utime))
}
