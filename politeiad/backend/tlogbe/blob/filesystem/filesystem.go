package filesystem

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/decred/politeia/politeiad/backend/tlogbe/blob"
)

var (
	_ blob.Blob = (*blobFilesystem)(nil)
)

// blobFilesystem implements the Blob interface using the filesystem.
type blobFilesystem struct {
	path string // Location of files
}

func (b *blobFilesystem) Put(key string, value []byte) error {
	return ioutil.WriteFile(filepath.Join(b.path, key), value, 0600)
}

func (b *blobFilesystem) PutMulti(blobs map[string][]byte) error {
	// TODO implement this
	return fmt.Errorf("not implemenated")
}

func (b *blobFilesystem) Get(key string) ([]byte, error) {
	blob, err := ioutil.ReadFile(filepath.Join(b.path, key))
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func (b *blobFilesystem) Del(key string) error {
	err := os.Remove(filepath.Join(b.path, key))
	if err != nil {
		// Always return not found
		return blob.ErrNotFound
	}
	return nil
}

func (b *blobFilesystem) Enum(f func(key string, value []byte) error) error {
	files, err := ioutil.ReadDir(b.path)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.Name() == ".." {
			continue
		}
		// TODO should we return filesystem errors or wrap them?
		blob, err := b.Get(file.Name())
		if err != nil {
			return err
		}
		err = f(file.Name(), blob)
		if err != nil {
			return err
		}
	}

	return nil
}

func BlobFilesystemNew(path string) *blobFilesystem {
	return &blobFilesystem{
		path: path,
	}
}
