package gitbe

import (
	"fmt"
	"io/ioutil"
	"os"
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
	t.Fatalf("FIXME")
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	_, err := g.gitInit("init")
	if err != nil {
		t.Fatal(err)
	}
}

func TestLog(t *testing.T) {
	log := btclog.NewBackend(&testWriter{t}).Logger("TEST")
	UseLogger(log)
	g := newGitBackEnd()
	defer os.RemoveAll(g.root)

	_, err := g.gitInit("log.test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = g.gitLog("log.test")
	if err == nil {
		t.Fatal("empty repo should fail log")
	}
}
