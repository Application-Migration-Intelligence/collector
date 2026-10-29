// Package walk finds the files the collector reads in an application folder.
//
// It never follows symbolic links, opens only regular files, stays inside
// the folder, and collects only the kinds of files the analysis uses (code,
// dependency manifests, build and server configuration). Data the analysis
// does not need, such as uploads, logs, caches, databases and media, is never read.
package walk

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Kinds of collected file.
const (
	KindSource = "source" // copied, with secrets masked
	KindEnv    = "env"    // replaced by its allowlisted driver settings
)

// Directories whose contents are not the application's own code. Their
// presence is recorded; their files are not read.
var excludedDirNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "vendor": true, "node_modules": true,
	".idea": true, ".vscode": true, ".cache": true,
}

// Folders that hold runtime data (uploads, logs, sessions, caches, builds).
var excludedDirPaths = map[string]bool{
	"storage": true, "bootstrap/cache": true, "public/build": true, "public/hot": true,
	"public/storage": true, "public/uploads": true,
}

var sourceExtensions = map[string]bool{
	".php": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".jsx": true,
	".tsx": true, ".vue": true, ".svelte": true, ".json": true, ".lock": true, ".yml": true,
	".yaml": true, ".xml": true, ".neon": true, ".dist": true, ".ini": true, ".conf": true,
	".toml": true, ".service": true, ".timer": true, ".sh": true, ".cron": true, ".stub": true,
}

var sourceNames = map[string]bool{
	"artisan": true, "Dockerfile": true, "Containerfile": true, "Procfile": true,
	"Makefile": true, "Caddyfile": true, "Vagrantfile": true, "crontab": true,
	".htaccess": true, ".nvmrc": true, ".node-version": true, ".php-version": true,
	".tool-versions": true, ".env.example": true, "composer.lock": true, "yarn.lock": true,
}

// Options bounds what is collected.
type Options struct {
	MaxFileBytes  int64 // larger files are skipped
	MaxTotalBytes int64 // collection stops here
	MaxFiles      int
}

// Defaults are generous for an application's own code and small enough for one upload.
var Defaults = Options{MaxFileBytes: 2 << 20, MaxTotalBytes: 512 << 20, MaxFiles: 100_000}

// File is one file the collector will read.
type File struct {
	Path string `json:"path"` // relative, forward slashes
	Size int64  `json:"size"`
	Kind string `json:"kind"`
	abs  string
	info fs.FileInfo
}

// Abs is the file's absolute path.
func (f File) Abs() string { return f.abs }

// Info is what the walk saw, to check that the file was not swapped before reading.
func (f File) Info() fs.FileInfo { return f.info }

// Skipped is a file or folder that was not read, and why.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result lists what will be read and what will not.
type Result struct {
	Root         string         `json:"-"`
	Files        []File         `json:"files"`
	Skipped      []Skipped      `json:"skipped"`
	ExcludedDirs []string       `json:"excluded_dirs"`
	NotCollected map[string]int `json:"not_collected"` // by extension: files of kinds the analysis does not use
	TotalBytes   int64          `json:"total_bytes"`
}

// Files that hold credentials and nothing the analysis needs.
var neverCollected = map[string]bool{"auth.json": true, ".npmrc": true, ".pgpass": true, ".my.cnf": true, ".netrc": true}

// Manifest reports whether a file is a dependency manifest or lock file,
// masked by secret format only (package names such as "ext-tokenizer"
// would trip the name-based rules and break the file).
func Manifest(rel string) bool {
	switch path.Base(rel) {
	case "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return true
	}
	return false
}

// Kind reports whether a file at rel (forward slashes) is collected, and how.
func Kind(rel string) (string, bool) {
	name := path.Base(rel)
	if neverCollected[name] {
		return "", false
	}
	if name == ".env" || (strings.HasPrefix(name, ".env.") && name != ".env.example") {
		return KindEnv, true
	}
	if sourceNames[name] || strings.HasPrefix(name, "Dockerfile") || strings.HasPrefix(name, "docker-compose") {
		return KindSource, true
	}
	return KindSource, sourceExtensions[strings.ToLower(path.Ext(name))]
}

// Walk lists the files under root that the collector reads.
func Walk(root string, opt Options) (*Result, error) {
	real, err := filepath.EvalSymlinks(root) // the folder itself may be a deploy symlink
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", root)
	}

	res := &Result{Root: real, NotCollected: map[string]int{}}
	limitHit := false

	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, walkErr error) error {
		rel, _ := filepath.Rel(real, p)
		rel = filepath.ToSlash(rel)
		if walkErr != nil {
			if p == real {
				return walkErr
			}
			res.Skipped = append(res.Skipped, Skipped{rel, reason(walkErr)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == real {
			return nil
		}
		mode := d.Type()
		switch {
		case mode&fs.ModeSymlink != 0:
			res.Skipped = append(res.Skipped, Skipped{rel, "symbolic link (not followed)"})
			return nil
		case d.IsDir():
			if excludedDirNames[d.Name()] || excludedDirPaths[rel] {
				res.ExcludedDirs = append(res.ExcludedDirs, rel)
				return fs.SkipDir
			}
			return nil
		case !mode.IsRegular():
			res.Skipped = append(res.Skipped, Skipped{rel, "not a regular file"})
			return nil
		}

		kind, ok := Kind(rel)
		if !ok {
			ext := strings.ToLower(path.Ext(rel))
			if ext == "" {
				ext = "(none)"
			}
			res.NotCollected[ext]++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			res.Skipped = append(res.Skipped, Skipped{rel, reason(err)})
			return nil
		}
		switch {
		case info.Size() > opt.MaxFileBytes:
			res.Skipped = append(res.Skipped, Skipped{rel, fmt.Sprintf("larger than %d bytes", opt.MaxFileBytes)})
		case limitHit || len(res.Files) >= opt.MaxFiles || res.TotalBytes+info.Size() > opt.MaxTotalBytes:
			limitHit = true
			res.Skipped = append(res.Skipped, Skipped{rel, "collection limit reached"})
		default:
			res.Files = append(res.Files, File{Path: rel, Size: info.Size(), Kind: kind, abs: p, info: info})
			res.TotalBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Path < res.Skipped[j].Path })
	sort.Strings(res.ExcludedDirs)
	return res, nil
}

// Read opens a listed file without following links and checks it is still the
// file the walk saw (not swapped for a link or another file in between).
func Read(f File, limit int64) ([]byte, error) {
	before, err := os.Lstat(f.abs)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || !os.SameFile(before, f.info) {
		return nil, errors.New("file changed after it was listed")
	}
	fh, err := os.Open(f.abs)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	after, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	buf := make([]byte, 0, min(after.Size(), limit)+1)
	data := buf
	chunk := make([]byte, 32*1024)
	for int64(len(data)) <= limit {
		n, err := fh.Read(chunk)
		data = append(data, chunk[:n]...)
		if err != nil {
			break
		}
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("grew beyond %d bytes while reading", limit)
	}
	return data, nil
}

func reason(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied"
	}
	return "unreadable: " + err.Error()
}
