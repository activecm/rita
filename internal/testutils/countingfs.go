package testutils

import (
	"os"
	"sync"

	"github.com/spf13/afero"
)

// CountingFS wraps an afero filesystem and counts the files opened and closed through it
type CountingFS struct {
	afero.Fs

	mu     sync.Mutex
	opened int
	closed int
}

func NewCountingFS(fs afero.Fs) *CountingFS {
	return &CountingFS{Fs: fs}
}

// Open opens a file and counts it
func (fs *CountingFS) Open(name string) (afero.File, error) {
	file, err := fs.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return fs.track(file), nil
}

// OpenFile opens a file with the given flags and counts it
func (fs *CountingFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	file, err := fs.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return fs.track(file), nil
}

// Create creates a file and counts it
func (fs *CountingFS) Create(name string) (afero.File, error) {
	file, err := fs.Fs.Create(name)
	if err != nil {
		return nil, err
	}
	return fs.track(file), nil
}

// GetCounts returns how many files were opened and closed.
// A file closed more than once counts once, so equal counts mean every file was closed
func (fs *CountingFS) GetCounts() (opened, closed int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.opened, fs.closed
}

// Unclosed returns how many files are still open
func (fs *CountingFS) Unclosed() int {
	opened, closed := fs.GetCounts()
	return opened - closed
}

func (fs *CountingFS) track(file afero.File) afero.File {
	fs.mu.Lock()
	fs.opened++
	fs.mu.Unlock()
	return &countedFile{File: file, fs: fs}
}

type countedFile struct {
	afero.File

	fs   *CountingFS
	once sync.Once
}

func (f *countedFile) Close() error {
	f.once.Do(func() {
		f.fs.mu.Lock()
		f.fs.closed++
		f.fs.mu.Unlock()
	})
	return f.File.Close()
}
