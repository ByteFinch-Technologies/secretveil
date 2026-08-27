//go:build !unix

package agefile

// lockDir does nothing on a system that has no advisory file lock. The release
// targets are darwin and linux, and both of them have one.
func lockDir(string) (func(), error) { return func() {}, nil }
