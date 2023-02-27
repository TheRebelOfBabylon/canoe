//go:build windows
// +build windows

package canoe

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetDirAvailableSpace will check the available space within a specified directory
func GetDirAvailableSpace(dir string) (uint64, error) {
	h := windows.MustLoadDLL("kernel32.dll")
	c := h.MustFindProc("GetDiskFreeSpaceExW")

	var freeBytes int64
	_, _, err := c.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(dir))), uintptr(unsafe.Pointer(&freeBytes)), nil, nil)
	if err != nil {
		return 0, err
	}
	return uint64(freeBytes), nil
}
