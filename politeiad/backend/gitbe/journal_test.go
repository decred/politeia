package gitbe

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testExact(j *Journal, filename string, count int) error {
	// Test replay exact
	err := j.Open(filename)
	if err != nil {
		return err
	}
	i := 0
	for ; ; i++ {
		err = j.Replay(filename, func(s string) error {
			ss := fmt.Sprintf("%v", i)
			if ss != s {
				return fmt.Errorf("not equal: %v %v", ss, s)
			}
			return nil
		})
		if err == io.EOF {
			if i > count {
				return fmt.Errorf("ran too many times")
			}
			break
		} else if err != nil {
			return err
		}
	}
	if i != count {
		return fmt.Errorf("invalid count: %v %v", i, count)
	}

	return nil
}

func TestJournalExact(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	t.Logf("TestJournalExact: %v", dir)
	if err != nil {
		t.Fatal(err)
	}
	j := NewJournal()

	// Test journal
	count := 1000
	filename := filepath.Join(dir, "file1")
	for i := 0; i < count; i++ {
		err = j.Journal(filename, fmt.Sprintf("%v", i))
		if err != nil {
			t.Fatalf("%v: %v", i, err)
		}
	}

	err = testExact(j, filename, count)
	if err != nil {
		t.Fatal(err)
	}

	err = j.Close(filename)
	if err != nil {
		t.Fatal(err)
	}

	os.RemoveAll(dir)
}

func TestJournalDoubleOpen(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestJournalDoubleOpen: %v", dir)

	j := NewJournal()
	filename := filepath.Join(dir, "file1")
	err = j.Journal(filename, "journal this")
	if err != nil {
		t.Fatal(err)
	}

	err = j.Open(filename)
	if err != nil {
		t.Fatal(err)
	}

	err = j.Open(filename)
	if err != ErrBusy {
		t.Fatal(err)
	}

	os.RemoveAll(dir)
}

func TestJournalDoubleClose(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestJournalDoubleClose: %v", dir)

	j := NewJournal()
	filename := filepath.Join(dir, "file1")
	err = j.Journal(filename, "journal this")
	if err != nil {
		t.Fatal(err)
	}

	err = j.Open(filename)
	if err != nil {
		t.Fatal(err)
	}

	err = j.Close(filename)
	if err != nil {
		t.Fatal(err)
	}

	err = j.Close(filename)
	if err != ErrNotFound {
		t.Fatal(err)
	}

	os.RemoveAll(dir)
}

func TestJournalConcurrent(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	t.Logf("TestJournalConcurrent: %v", dir)
	if err != nil {
		t.Fatal(err)
	}

	j := NewJournal()
	// Test concurrent writes
	files := 10
	count := 1000
	var wg sync.WaitGroup
	for i := 0; i < files; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			filename := filepath.Join(dir, fmt.Sprintf("file%v", k))
			for k := 0; k < count; k++ {
				err := j.Journal(filename, fmt.Sprintf("%v", k))
				if err != nil {
					t.Fatal(err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Test concurrent reads
	t.Logf("TestJournalConcurrent: reading back %v", dir)
	for i := 0; i < files; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			filename := filepath.Join(dir, fmt.Sprintf("file%v", k))
			err := testExact(j, filename, count)
			if err != nil {
				t.Fatal(err)
			}
		}(i)
	}

	wg.Wait()

	// Close concurrent
	t.Logf("TestJournalConcurrent: closing %v", dir)
	for i := 0; i < files; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			filename := filepath.Join(dir, fmt.Sprintf("file%v", k))
			err := j.Close(filename)
			if err != nil {
				t.Fatal(err)
			}
		}(i)
	}

	wg.Wait()

	os.RemoveAll(dir)
}

func TestJournalConcurrentSame(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	t.Logf("TestJournalConcurrentSame: %v", dir)
	if err != nil {
		t.Fatal(err)
	}

	j := NewJournal()

	var wg sync.WaitGroup
	count := 10000
	check := make(map[int]struct{})
	filename := filepath.Join(dir, "file1")
	for i := 0; i < count; i++ {
		wg.Add(1)
		check[i] = struct{}{}
		go func(k int) {
			defer wg.Done()
			err := j.Journal(filename, fmt.Sprintf("%v", k))
			if err != nil {
				t.Fatalf("%v: %v", k, err)
			}
		}(i)
	}

	wg.Wait()

	// Read back and make sure all entries exist
	err = j.Open(filename)
	if err != nil {
		t.Fatal(err)
	}

	i := 0
	for ; ; i++ {
		err = j.Replay(filename, func(s string) error {
			delete(check, i)
			return nil
		})
		if err == io.EOF {
			if i > count {
				t.Fatalf("ran too many times")
			}
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if i != count {
		t.Fatalf("invalid count: %v %v", i, count)
	}
	if len(check) != 0 {
		t.Fatalf("len != 0")
	}

	os.RemoveAll(dir)
}

func TestJournalCopy(t *testing.T) {
	dir, err := ioutil.TempDir("", "journal")
	t.Logf("TestJournalConcurrentCopy: %v", dir)
	if err != nil {
		t.Fatal(err)
	}

	j := NewJournal()

	// Test journal
	count := 1000
	filename := filepath.Join(dir, "file1")
	for i := 0; i < count; i++ {
		err = j.Journal(filename, fmt.Sprintf("%v", i))
		if err != nil {
			t.Fatalf("%v: %v", i, err)
		}
	}

	err = testExact(j, filename, count)
	if err != nil {
		t.Fatal(err)
	}

	err = j.Close(filename)
	if err != nil {
		t.Fatal(err)
	}

	// Copy journal fail
	destination := filepath.Join(dir, "") // Try to overwrite dir
	err = j.Copy(filename, destination)
	if err == nil {
		t.Fatalf("Expected error")
	}

	// Copy journal fail 2
	destination = filepath.Join(dir, "d", "..", "file1") // Try to overwrite same file
	err = j.Copy(filename, destination)
	if err != ErrSameFile {
		t.Fatalf("Expected ErrSameFile")
	}

	// Copy journal
	destination = filepath.Join(dir, "file2")
	err = j.Copy(filename, destination)
	if err != nil {
		t.Fatal(err)
	}

	// Test Copy
	err = testExact(j, destination, count)
	if err != nil {
		t.Fatal(err)
	}

	os.RemoveAll(dir)
}
