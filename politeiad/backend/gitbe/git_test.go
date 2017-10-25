package gitbe

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btclog"
)

type testWriter struct {
	t *testing.T
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

func newGitBackEnd() *gitBackEnd {
	dir, err := ioutil.TempDir("", "politeiad.test")
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	return &gitBackEnd{
		root:     dir,
		gitPath:  "git", // assume installed
		gitTrace: true,
	}
}

func TestVersion(t *testing.T) {
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	_, err := g.gitVersion()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInit(t *testing.T) {
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	_, err := g.gitInit(g.root)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLog(t *testing.T) {
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	_, err := g.gitInit(g.root)
	if err != nil {
		t.Fatal(err)
	}

	_, err = g.gitLog(g.root)
	if err == nil {
		t.Fatal("empty repo should fail log")
	}
}

func TestFsck(t *testing.T) {
	// Test git fsck, we build on top of that with a dcrtime fsck
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	// Init git repo
	_, err := g.gitInit(g.root)
	if err != nil {
		t.Fatal(err)
	}

	// Create a file in repo
	tf := filepath.Join(g.root, "testfile")
	t.Logf("fsck location: %v", tf)
	err = ioutil.WriteFile(tf, []byte("this is a test\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Git add file
	err = g.gitAdd(g.root, tf)
	if err != nil {
		t.Fatal(err)
	}

	// Git commit
	err = g.gitCommit(g.root, "Add testfile")
	if err != nil {
		t.Fatal(err)
	}

	// First mess up refs by reading file in memry and then corrupting it
	masterFilename := filepath.Join(g.root, ".git/refs/heads/master")
	master, err := ioutil.ReadFile(masterFilename)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt master
	masterCorrupt := make([]byte, len(master))
	for k := range masterCorrupt {
		masterCorrupt[k] = '0'
	}
	err = ioutil.WriteFile(masterFilename, masterCorrupt, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Expect fsck to fail
	_, err = g.gitFsck(g.root)
	if err == nil {
		t.Fatalf("expected fsck error")
	}

	// Restore master
	err = ioutil.WriteFile(masterFilename, master, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Expect fsck to work again
	_, err = g.gitFsck(g.root)
	if err != nil {
		t.Fatal(err)
	}

	// Use git cat-file to fish out the types and values from objects.

	// First find the last commit
	out, err := g.git(g.root, "log", "--pretty=oneline")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.SplitN(out[0], " ", 2)
	comitHash := s[0]

	// Get type
	out, err = g.git(g.root, "cat-file", "-t", comitHash)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != "commit" {
		t.Fatalf("invalid type: %v", string(out[0]))
	}

	// Now get the tree object
	out, err = g.git(g.root, "cat-file", "-p", comitHash)
	if err != nil {
		t.Fatal(err)
	}
	s = strings.SplitN(out[0], " ", 2)
	treeHash := s[1]

	out, err = g.git(g.root, "cat-file", "-t", treeHash)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != "tree" {
		t.Fatalf("invalid type: %v", string(out[0]))
	}

	// Now go get the blob
	out, err = g.git(g.root, "cat-file", "-p", treeHash)
	if err != nil {
		t.Fatal(err)
	}
	// out = 100644 blob 90bfcb510602aa11ae53a42dcec18ea39fbd8cec\ttestfile
	s = strings.Split(out[0], "\t")
	s = strings.Split(s[0], " ")
	blobHash := s[2]

	out, err = g.git(g.root, "cat-file", "-t", blobHash)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != "blob" {
		t.Fatalf("invalid type: %v", string(out[0]))
	}

	// Now we corrupt the blob object
	blobObjectFilename := filepath.Join(g.root, ".git", "objects",
		blobHash[:2], blobHash[2:])
	blobObject, err := ioutil.ReadFile(blobObjectFilename)
	if err != nil {
		t.Fatal(err)
	}
	// Make a copy to uncorrupt later
	xxx := make([]byte, len(blobObject))
	copy(xxx, blobObject)

	// Uncompress
	b := bytes.NewBuffer(xxx)
	r, err := zlib.NewReader(b)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	io.Copy(w, r)
	r.Close()
	// buf now contains a header + the text we shoved in it.  We are going
	// to use this later to corrupt the file by uppercasing the last
	// letter.

	// Make file writable
	err = os.Chmod(blobObjectFilename, 0644)
	if err != nil {
		t.Fatal(err)
	}
	location := len(blobObject) - 2 // zlib error
	blobObject[location] = ^blobObject[location]
	err = ioutil.WriteFile(blobObjectFilename, blobObject, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Expect fsck to fail
	_, err = g.gitFsck(g.root)
	if err == nil {
		t.Fatalf("expected fsck error")
	}

	// Now write buf back with capitalized letter at the end
	copy(blobObject, xxx) // restore blob object
	corruptBuf := buf.Bytes()
	location = len(corruptBuf) - 2 // account for \n
	corruptBuf[location] = corruptBuf[location] & 0xdf

	var bc bytes.Buffer
	w2, err := zlib.NewWriterLevel(&bc, 1) // git uses zlib level 1
	if err != nil {
		t.Fatal(err)
	}
	w2.Write(corruptBuf)
	w2.Close()

	// Write corrupt zlib data
	err = ioutil.WriteFile(blobObjectFilename, bc.Bytes(), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Expect fsck to fail
	_, err = g.gitFsck(g.root)
	if err == nil {
		t.Fatalf("expected fsck error")
	}

	// Restore object
	err = ioutil.WriteFile(blobObjectFilename, xxx, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Expect fsck to fail
	_, err = g.gitFsck(g.root)
	if err != nil {
		t.Fatal(err)
	}
}
