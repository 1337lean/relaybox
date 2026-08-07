//go:build windows

package store

import (
	"os"
	"syscall"
)

// Windows denies renames and replacements while any open handle was created
// without FILE_SHARE_DELETE. The store relies on replacement for compaction
// and deliberately keeps all reads on the opened handle, so grant delete
// sharing while retaining exclusive ownership at the application level.
func openStoreFile(path string, create bool) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	creation := uint32(syscall.OPEN_EXISTING)
	if create {
		creation = syscall.OPEN_ALWAYS
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		creation,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
