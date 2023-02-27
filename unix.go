//go:build !windows
// +build !windows

package canoe

import (
	"golang.org/x/sys/unix"
)

// GetDirAvailableSpace will check the available space within a specified directory
func GetDirAvailableSpace(dir string) (uint64, error) {
	var stat unix.Statfs_t
	unix.Statfs(dir, &stat)
	return stat.Bavail * uint64(stat.Bsize), nil
}
