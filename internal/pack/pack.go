// Package pack writes the collector package: a gzipped tar archive with the
// application's collected files (secrets masked), the server's facts and
// configuration files, and a manifest of everything included or left out.
//
// Format "mig.collector.package" 1.0.0, documented in docs/package-format.md.
package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Application-Migration-Intelligence/collector/internal/envfile"
	"github.com/Application-Migration-Intelligence/collector/internal/facts"
	"github.com/Application-Migration-Intelligence/collector/internal/redact"
	"github.com/Application-Migration-Intelligence/collector/internal/walk"
)

// Format names this package format; FormatVersion follows the same rules as
// the engine result contract: new fields bump the minor version, anything else
// the major.
const (
	Format        = "mig.collector.package"
	FormatVersion = "1.0.0"
	MediaType     = "application/vnd.mig.collector-package+gzip"
)

// Entry is one file in the package.
type Entry struct {
	Path       string `json:"path"`       // path in the application, or absolute path on the server
	Stored     string `json:"stored"`     // path inside the archive
	Kind       string `json:"kind"`       // source | env | server-config
	Size       int64  `json:"size"`       // bytes stored, after masking
	SHA256     string `json:"sha256"`     // of the stored bytes
	Redactions int    `json:"redactions"` // values masked
	Dropped    int    `json:"env_keys_dropped,omitempty"`
}

// Manifest is manifest.json, the last entry in the archive.
type Manifest struct {
	Format        string         `json:"format"`
	FormatVersion string         `json:"format_version"`
	Collector     CollectorInfo  `json:"collector"`
	CreatedAt     string         `json:"created_at"`
	Application   string         `json:"application"` // folder name only
	Files         []Entry        `json:"files"`
	ServerFiles   []Entry        `json:"server_files"`
	Skipped       []walk.Skipped `json:"skipped"`
	ExcludedDirs  []string       `json:"excluded_dirs"`
	NotCollected  map[string]int `json:"not_collected"`
	Totals        Totals         `json:"totals"`
}

// CollectorInfo identifies the binary that wrote the package.
type CollectorInfo struct {
	Version string `json:"version"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Totals summarises the package.
type Totals struct {
	Files          int   `json:"files"`
	ServerFiles    int   `json:"server_files"`
	Bytes          int64 `json:"bytes"`
	Redactions     int   `json:"redactions"`
	EnvKeysDropped int   `json:"env_keys_dropped"`
}

// Options for Write.
type Options struct {
	Version        string
	Now            time.Time
	SysRoot        string // "/" on a real server; server config paths are relative to it
	MaxConfigBytes int64
}

// Write streams the package to w. The application's files go first, then the
// server's configuration files and server.json, then manifest.json.
func Write(ctx context.Context, w io.Writer, res *walk.Result, f *facts.Facts, opt Options) (*Manifest, error) {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Header.ModTime = time.Time{} // reproducible archives
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)

	m := &Manifest{
		Format:        Format,
		FormatVersion: FormatVersion,
		Collector:     CollectorInfo{Version: opt.Version, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH},
		CreatedAt:     opt.Now.UTC().Format(time.RFC3339),
		Application:   filepath.Base(res.Root),
		Files:         []Entry{},
		ServerFiles:   []Entry{},
		Skipped:       append([]walk.Skipped{}, res.Skipped...),
		ExcludedDirs:  append([]string{}, res.ExcludedDirs...),
		NotCollected:  res.NotCollected,
	}

	for _, file := range res.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := walk.Read(file, file.Size+1)
		if err != nil {
			m.Skipped = append(m.Skipped, walk.Skipped{Path: file.Path, Reason: "not read: " + err.Error()})
			continue
		}
		entry := Entry{Path: file.Path, Kind: file.Kind}
		switch {
		case file.Kind == walk.KindEnv:
			data, entry.Dropped = envfile.Filter(data)
			m.Totals.EnvKeysDropped += entry.Dropped
		case isBinary(data):
			m.Skipped = append(m.Skipped, walk.Skipped{Path: file.Path, Reason: "binary file"})
			continue
		default:
			mask := redact.Text
			if walk.Manifest(file.Path) {
				mask = redact.Formats
			}
			var text string
			text, entry.Redactions = mask(string(data))
			data = []byte(text)
		}
		entry.Stored = "source/" + file.Path
		if err := add(tw, entry.Stored, data); err != nil {
			return nil, err
		}
		fill(&entry, data)
		m.Files = append(m.Files, entry)
		m.Totals.Bytes += entry.Size
		m.Totals.Redactions += entry.Redactions
	}

	if f != nil {
		for _, cf := range f.ConfigFiles {
			data, err := readServerFile(filepath.Join(opt.SysRoot, filepath.FromSlash(strings.TrimPrefix(cf.Path, "/"))), opt.MaxConfigBytes)
			if err != nil {
				m.Skipped = append(m.Skipped, walk.Skipped{Path: cf.Path, Reason: "not read: " + err.Error()})
				continue
			}
			text, n := redact.Text(string(data))
			entry := Entry{Path: cf.Path, Kind: "server-config", Redactions: n, Stored: "server/files" + path.Clean(cf.Path)}
			data = []byte(text)
			if err := add(tw, entry.Stored, data); err != nil {
				return nil, err
			}
			fill(&entry, data)
			m.ServerFiles = append(m.ServerFiles, entry)
			m.Totals.Bytes += entry.Size
			m.Totals.Redactions += n
		}

		// Command output can hold secrets too (a crontab line with a token).
		masked := *f
		masked.Commands = map[string]facts.Command{}
		for name, c := range f.Commands {
			c.Output, _ = redact.Text(c.Output)
			masked.Commands[name] = c
		}
		data, err := json.MarshalIndent(masked, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := add(tw, "server.json", data); err != nil {
			return nil, err
		}
	}

	m.Totals.Files = len(m.Files)
	m.Totals.ServerFiles = len(m.ServerFiles)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := add(tw, "manifest.json", data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

func add(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func fill(e *Entry, data []byte) {
	sum := sha256.Sum256(data)
	e.SHA256 = hex.EncodeToString(sum[:])
	e.Size = int64(len(data))
}

func isBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// readServerFile opens a configuration file without following a link at the
// last step, and refuses anything that is not a regular file of bounded size.
func readServerFile(p string, max int64) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	after, err := fh.Stat()
	if err != nil || !os.SameFile(st, after) {
		return nil, errors.New("file changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return data, nil
}
