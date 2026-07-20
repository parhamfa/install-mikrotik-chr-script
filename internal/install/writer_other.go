//go:build !linux

package install

import "fmt"

func RunWriter(_ string, _ bool) error {
	return fmt.Errorf("the destructive writer is only available on Linux")
}

func HaltWriter(err error) {
	panic(err)
}
