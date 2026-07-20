package install

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

type ProgressFunc func(written, total int64)

func CopyImage(source io.Reader, target io.Writer, total int64, progress ProgressFunc) (string, error) {
	if total <= 0 {
		return "", fmt.Errorf("invalid image size")
	}
	hash := sha256.New()
	buffer := make([]byte, 4*1024*1024)
	var written int64
	for written < total {
		remaining := total - written
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		count, readErr := io.ReadFull(source, chunk)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return "", readErr
		}
		if count == 0 {
			return "", io.ErrUnexpectedEOF
		}
		part := chunk[:count]
		if _, err := hash.Write(part); err != nil {
			return "", err
		}
		countWritten, err := target.Write(part)
		if err != nil {
			return "", err
		}
		if countWritten != len(part) {
			return "", io.ErrShortWrite
		}
		written += int64(count)
		if progress != nil {
			progress(written, total)
		}
		if readErr == io.ErrUnexpectedEOF && written != total {
			return "", io.ErrUnexpectedEOF
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func HashPrefix(source io.Reader, size int64, progress ProgressFunc) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("invalid verification size")
	}
	hash := sha256.New()
	buffer := make([]byte, 4*1024*1024)
	var read int64
	for read < size {
		remaining := size - read
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		count, err := io.ReadFull(source, chunk)
		if err != nil && err != io.ErrUnexpectedEOF {
			return "", err
		}
		if count == 0 {
			return "", io.ErrUnexpectedEOF
		}
		_, _ = hash.Write(chunk[:count])
		read += int64(count)
		if progress != nil {
			progress(read, size)
		}
		if err == io.ErrUnexpectedEOF && read != size {
			return "", io.ErrUnexpectedEOF
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
