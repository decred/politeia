// Copyright (c) 2017-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitError contains all the components of a git invocation.
type gitError struct {
	cmd    []string
	stdout []string
	stderr []string
}

// log pretty prints a gitError.
func (e gitError) log() {
	var cmd string
	for _, v := range e.cmd {
		cmd += v + " "
	}
	log.Infof("Git command     : %v", cmd)
	s := "Git stdout :"
	for _, v := range e.stdout {
		log.Infof("%v %v", s, v)
		s = ""
	}
	s = "Git stderr :"
	for _, v := range e.stderr {
		log.Infof("%v %v", s, v)
		s = ""
	}
}

func outputReader(r io.Reader) ([]string, error) {
	rv := make([]string, 0, 128)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		rv = append(rv, scanner.Text())
	}
	return rv, scanner.Err()
}

// git excutes the git command using the provided arguments.  If the path
// argument is set it'll be copied to the GIT_DIR environment variable.
func (g *gitBackEnd) git(path string, args ...string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("git requires arguments")
	}

	// Setup gitError
	ge := gitError{
		cmd:    make([]string, 0, len(args)+1),
		stdout: make([]string, 0, 128),
		stderr: make([]string, 0, 128),
	}

	ge.cmd = append(ge.cmd, g.gitPath)
	ge.cmd = append(ge.cmd, args...)

	if g.gitTrace {
		defer func() { ge.log() }()
	}

	// Execute git command
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(g.gitPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Determine if we need to set GIT_DIR
	if path != "" {
		cmd.Dir = path
	}

	doneError := cmd.Run()

	// Prepare output
	var err error
	ge.stdout, err = outputReader(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		log.Errorf("git stdout scanner error: %v", err)
	}
	ge.stderr, err = outputReader(bytes.NewReader(stderr.Bytes()))
	if err != nil {
		log.Errorf("git stderr scanner error: %v", err)
	}

	return ge.stdout, doneError
}

// gitVersion returns the version of git.
func (g *gitBackEnd) gitVersion() (string, error) {
	out, err := g.git("", "version")
	if err != nil {
		return "", err
	}

	if len(out) != 1 {
		return "", fmt.Errorf("unexpected git output")
	}

	return out[0], nil
}

func (g *gitBackEnd) gitHasChanges(path string) (rv bool) {
	if _, err := g.git(path, "diff", "--quiet"); err != nil {
		rv = true
	} else if _, err := g.git(path, "diff", "--cached",
		"--quiet"); err != nil {
		rv = true
	}
	return rv
}

func (g *gitBackEnd) gitDiff(path string) ([]string, error) {
	return g.git(path, "diff")
}

func (g *gitBackEnd) gitStash(path string) error {
	_, err := g.git(path, "stash")
	return err
}

func (g *gitBackEnd) gitStashDrop(path string) error {
	_, err := g.git(path, "stash", "drop")
	return err
}

func (g *gitBackEnd) gitRm(path, filename string, force bool) error {
	var err error
	if force {
		_, err = g.git(path, "rm", "-f", filename)
	} else {
		_, err = g.git(path, "rm", filename)
	}
	return err
}

func (g *gitBackEnd) gitAdd(path, filename string) error {
	_, err := g.git(path, "add", filename)
	return err
}

func (g *gitBackEnd) gitCommit(path, message string) error {
	_, err := g.git(path, "commit", "-m", message)
	return err
}

func (g *gitBackEnd) gitCheckout(path, branch string) error {
	_, err := g.git(path, "checkout", branch)
	return err
}

func (g *gitBackEnd) gitBranchDelete(path, branch string) error {
	_, err := g.git(path, "branch", "-D", branch)
	return err
}

func (g *gitBackEnd) gitClean(path string) error {
	_, err := g.git(path, "clean", "-xdf")
	return err
}

func (g *gitBackEnd) gitBranches(path string) ([]string, error) {
	branches, err := g.git(path, "branch")
	if err != nil {
		return nil, err
	}

	b := make([]string, 0, len(branches))
	for _, v := range branches {
		b = append(b, strings.Trim(v, " *\t\n"))
	}

	return b, nil
}

func (g *gitBackEnd) gitBranchNow(path string) (string, error) {
	branches, err := g.git(path, "branch")
	if err != nil {
		return "", err
	}

	for _, v := range branches {
		if strings.Contains(v, "*") {
			return strings.Trim(v, " *\t\n"), nil
		}
	}

	return "", fmt.Errorf("unexpected git output")
}

func (g *gitBackEnd) gitPull(path string, fastForward bool) error {
	var err error
	if fastForward {
		_, err = g.git(path, "pull", "--ff-only", "--rebase")
	} else {
		_, err = g.git(path, "pull")
	}
	if err != nil {
		return err
	}

	return nil
}

func (g *gitBackEnd) gitRebase(path, branch string) error {
	_, err := g.git(path, "rebase", branch)
	return err
}

func (g *gitBackEnd) gitPush(path, remote, branch string, upstream bool) error {
	var err error
	if upstream {
		_, err = g.git(path, "push", "--set-upstream", remote, branch)
	} else {
		_, err = g.git(path, "push")
	}
	if err != nil {
		return err
	}

	return nil
}

func (g *gitBackEnd) gitUnwind(path string) error {
	_, err := g.git(path, "checkout", "-f")
	if err != nil {
		return err
	}
	return g.gitClean(path)
}

func (g *gitBackEnd) gitUnwindBranch(path, branch string) error {
	err := g.gitUnwind(path)
	if err != nil {
		return err
	}
	err = g.gitCheckout(path, "master")
	if err != nil {
		return err
	}
	return g.gitBranchDelete(path, branch)
}

func (g *gitBackEnd) gitNewBranch(path, branch string) error {
	_, err := g.git(path, "checkout", "-b", branch)
	return err
}

func (g *gitBackEnd) gitLastDigest(path string) ([]byte, error) {
	out, err := g.git(path, "log", "--pretty=oneline", "-n 1")
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid git output")
	}

	// Returned data is "<digest> <commit message>"
	ds := strings.SplitN(out[0], " ", 2)
	if len(ds) == 0 {
		return nil, fmt.Errorf("invalid log")
	}

	d, err := hex.DecodeString(ds[0])
	if err != nil {
		return nil, err
	}

	if len(d) != sha1.Size {
		return nil, fmt.Errorf("invalid sha1 size")
	}

	return d, nil
}

func (g *gitBackEnd) gitLog(path string) ([]string, error) {
	out, err := g.git(path, "log")
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (g *gitBackEnd) gitFsck(path string) ([]string, error) {
	out, err := g.git(path, "fsck", "--full", "--strict")
	if err != nil {
		return nil, err
	}

	return out, nil
}

// gitConfig sets a config value for the provided repo.
func (g *gitBackEnd) gitConfig(path, name, value string) error {
	_, err := g.git(path, "config", name, value)
	return err
}

// gitClone clones a git repository.  This functions exits without an error
// if the directory is already a git repo.
func (g *gitBackEnd) gitClone(from, to string, repoConfig map[string]string) error {
	_, err := os.Stat(filepath.Join(from, ".git"))
	if os.IsNotExist(err) {
		return fmt.Errorf("source repo does not exist")
	}
	_, err = os.Stat(filepath.Join(to, ".git"))
	if !os.IsNotExist(err) {
		return err
	}

	log.Infof("Cloning git repo %v to %v", from, to)

	// Clone the repo (with config, if applicable).
	args := []string{"clone", from, to}
	for k, v := range repoConfig {
		args = append(args, "-c", k+"="+v)
	}
	_, err = g.git("", args...)
	return err
}

// gitInit initializes a new repository.  If the repository exists
// it does not reinit it; it reutns failure instead.
func (g *gitBackEnd) gitInit(path string) (string, error) {
	out, err := g.git("", "init", path)
	if err != nil {
		return "", err
	}

	if len(out) != 1 {
		return "", fmt.Errorf("unexpected git output")
	}

	return out[0], nil
}

// gitInitRepo initializes a directory as a git repo.  This functions exits
// without an error if the directory is already a git repo.  The git repo is
// initialized with a .gitignore file so that a) have a master and b) always
// ignore the lock file.
func (g *gitBackEnd) gitInitRepo(path string, repoConfig map[string]string) error {
	_, err := os.Stat(filepath.Join(path, ".git"))
	// This test is unreadable but correct.
	if !os.IsNotExist(err) {
		return err
	}

	// Containing directory
	log.Infof("Initializing git repo: %v", path)
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return err
	}

	// Initialize git repo
	_, err = g.gitInit(path)
	if err != nil {
		return err
	}

	// Apply repo config
	for k, v := range repoConfig {
		err = g.gitConfig(path, k, v)
		if err != nil {
			return err
		}
	}

	// Add empty .gitignore
	// This makes the repo ready to go and we'll always use this as the
	// initial commit.
	err = ioutil.WriteFile(filepath.Join(path, ".gitignore"), []byte{},
		0664)
	if err != nil {
		return err
	}
	err = g.gitAdd(path, ".gitignore")
	if err != nil {
		return err
	}

	err = g.gitCommit(path, "Add .gitignore")
	if err != nil {
		return err
	}

	// Add README.md
	err = ioutil.WriteFile(filepath.Join(path, "README.md"),
		[]byte(defaultReadme), 0644)
	if err != nil {
		return err
	}
	err = g.gitAdd(path, "README.md")
	if err != nil {
		return err
	}

	return g.gitCommit(path, "Add README.md")
}
