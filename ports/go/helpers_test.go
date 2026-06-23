package main

import "os"

// osWriteFile is a tiny test helper kept in its own file to confine the os
// import to test code.
func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
