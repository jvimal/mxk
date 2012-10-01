//
// Written by Maxim Khitrov (September 2012)
//

package pbkdf2

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetCurrentThread = modkernel32.NewProc("GetCurrentThread")
	procGetThreadTimes   = modkernel32.NewProc("GetThreadTimes")
)

func threadUtime() time.Duration {
	var u syscall.Rusage
	h, _ := getCurrentThread()
	err := getThreadTimes(h, &u.CreationTime, &u.ExitTime, &u.KernelTime, &u.UserTime)
	if err != nil {
		panic(err)
	}
	t := uint64(u.UserTime.HighDateTime)<<32 | uint64(u.UserTime.LowDateTime)
	return time.Duration(t * 100)
}

func getCurrentThread() (pseudoHandle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetCurrentThread.Addr(), 0, 0, 0, 0)
	pseudoHandle = syscall.Handle(r0)
	if pseudoHandle == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func getThreadTimes(handle syscall.Handle, creationTime *syscall.Filetime, exitTime *syscall.Filetime, kernelTime *syscall.Filetime, userTime *syscall.Filetime) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetThreadTimes.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(exitTime)), uintptr(unsafe.Pointer(kernelTime)), uintptr(unsafe.Pointer(userTime)), 0)
	if int(r1) == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
