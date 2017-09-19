package gitbe

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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
	//defer os.RemoveAll(g.root)

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
}
