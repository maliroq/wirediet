package safeio

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAtomicWritePrivateRejectsDestinationSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require privileges")
	}
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWritePrivate(link, []byte("replacement")); err == nil {
		t.Fatal("expected destination symlink rejection")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "original" {
		t.Fatal("symlink target was modified")
	}
}

func TestAtomicWritePrivateRejectsRelativeSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require privileges")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := AtomicWritePrivate(filepath.Join("linked", "state.json"), []byte("{}")); err == nil {
		t.Fatal("expected relative symlink-parent rejection")
	}
}
