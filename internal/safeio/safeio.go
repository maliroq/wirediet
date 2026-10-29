package safeio

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ReadFileLimit reads at most max bytes. It rejects larger regular files before
// allocation and also caps streamed reads so special files cannot bypass the
// limit.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if st.Mode().IsRegular() && st.Size() > max {
		return nil, fmt.Errorf("file exceeds %d-byte safety limit", max)
	}

	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file exceeds %d-byte safety limit", max)
	}
	return b, nil
}

// RejectUnsafeSymlinkParents rejects suspicious output parents without
// breaking normal platform paths that contain system symlinks. Relative paths
// are checked component-by-component. For absolute paths, the nearest existing
// ancestor is checked; this catches a symlink used as the immediate output
// parent while allowing paths such as macOS /var/... where an earlier system
// component is itself a symlink.
func RejectUnsafeSymlinkParents(path string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		cur := filepath.Dir(clean)
		for {
			st, err := os.Lstat(cur)
			if err == nil {
				if st.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("refusing output path with symlink nearest ancestor %q", cur)
				}
				if !st.IsDir() {
					return fmt.Errorf("refusing output path with non-directory ancestor %q", cur)
				}
				return nil
			}
			if !os.IsNotExist(err) {
				return err
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				return nil
			}
			cur = parent
		}
	}
	parent := filepath.Dir(clean)
	if parent == "." || parent == "" {
		return nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cur := cwd
	for _, part := range strings.Split(parent, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing relative output path containing symlink parent %q", cur)
		}
		if !st.IsDir() {
			return fmt.Errorf("refusing output path with non-directory parent %q", cur)
		}
	}
	return nil
}

// AtomicWritePrivate replaces path without following a pre-existing symlink at
// the destination. The temporary file is owner-only and is renamed into place.
func AtomicWritePrivate(path string, data []byte) error {
	if err := RejectUnsafeSymlinkParents(path); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || st.IsDir() {
			return fmt.Errorf("refusing symlink or directory destination %q", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, ".wirediet-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Windows does not replace an existing destination with Rename. Removing a
	// destination symlink removes the link itself, not its target.
	if runtime.GOOS == "windows" {
		if st, err := os.Lstat(path); err == nil {
			if st.IsDir() {
				return fmt.Errorf("refusing to replace directory %q", path)
			}
			if err := os.Remove(path); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return os.Chmod(path, 0o600)
}
