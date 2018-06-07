package gitbe

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrBusy     = fmt.Errorf("busy")
	ErrNotFound = fmt.Errorf("not found")
	ErrSameFile = fmt.Errorf("source same as destination")
)

type journalFile struct {
	file    *os.File
	scanner *bufio.Scanner
}

// Journal is a generic 1:N file journaler. It uses an in memory mutex to
// coordinate all actions on disk. The journaler assumes text files that are
// "\n" delineated.
type Journal struct {
	sync.Mutex
	journals map[string]*journalFile
}

// NewJournal creates a new Journal context. One can use a single journal
// context for many journals.
func NewJournal() *Journal {
	return &Journal{
		journals: make(map[string]*journalFile),
	}
}

// Journal writes content to a journal file. Note that content should not be
// bigger than bufio.Scanner can read per line. If the user does not provide
// "\n" at the end of content string, this function appends it.
func (j *Journal) Journal(filename, content string) error {
	j.Lock()
	defer j.Unlock()

	if _, ok := j.journals[filename]; ok {
		return ErrBusy
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	_, err = f.Write([]byte(content))
	return err
}

// Open opens a journal file ready for replay.  Once done replaying the journal
// the journal file needs to be closed. Note that if the journal is open writes
// return ErrBusy.
func (j *Journal) Open(filename string) error {
	j.Lock()
	defer j.Unlock()

	if _, ok := j.journals[filename]; ok {
		return ErrBusy
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}

	j.journals[filename] = &journalFile{
		file:    f,
		scanner: bufio.NewScanner(f),
	}

	return nil
}

// Close closes the underlying journal file. If the journal file is not found
// the function returns ErrNotFound.
func (j *Journal) Close(filename string) error {
	j.Lock()
	defer j.Unlock()

	f, ok := j.journals[filename]
	if !ok {
		return ErrNotFound
	}
	delete(j.journals, filename)
	return f.file.Close()
}

// Replay reads a single line from the journal file and calls the replay
// function that was provided. If the scanner encounters EOF it returns EOF,
// unlike the scanner API.
func (j *Journal) Replay(filename string, replay func(string) error) error {
	j.Lock()
	f, ok := j.journals[filename]
	if !ok {
		j.Unlock()
		return ErrNotFound
	}
	j.Unlock()

	// We can run unlocked from here

	if !f.scanner.Scan() {
		if f.scanner.Err() == nil {
			return io.EOF
		}
		return f.scanner.Err()
	}

	return replay(f.scanner.Text())
}

// Copy copies a journal file from source to destination. During the copy
// process the source file remains locked. This call has the same error
// semantics as the Open call.
func (j *Journal) Copy(source, destination string) (err error) {
	err = j.Open(source)
	if err != nil {
		return
	}
	defer func() {
		cerr := j.Close(source)
		if cerr != nil {
			err = cerr
		}
	}()

	err = fileCopy(source, destination)
	return
}

// fileCopy copies a file from src to dst. It attempts to detect if the source
// and destination filename are the same and will return ErrSameFile if they
// are. This test can be defeated and it is meant as basic bug detector.
func fileCopy(srcName, dstName string) (err error) {
	// Try a little bit to prevent overwriting the same file.
	src := filepath.Clean(srcName)
	dst := filepath.Clean(dstName)
	if src == dst {
		err = ErrSameFile
		return
	}
	var in, out *os.File
	in, err = os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err = os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if cerr == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
