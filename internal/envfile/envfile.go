// Package envfile reads environment files for an allowlist of non-secret keys.
//
// `.env` files are full of credentials. The collector never copies them: it
// writes a replacement holding only keys that name drivers or versions, the
// same allowlist the MigrateIntel engine reads (core/envfile.py).
package envfile

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strings"
)

// Allowed are the keys whose values name drivers or versions, never credentials.
var Allowed = map[string]bool{
	"APP_ENV": true, "DB_CONNECTION": true, "CACHE_DRIVER": true, "CACHE_STORE": true,
	"QUEUE_CONNECTION": true, "QUEUE_DRIVER": true, "SESSION_DRIVER": true,
	"FILESYSTEM_DISK": true, "FILESYSTEM_DRIVER": true, "FILESYSTEM_CLOUD": true,
	"MAIL_MAILER": true, "MAIL_DRIVER": true, "BROADCAST_CONNECTION": true,
	"BROADCAST_DRIVER": true, "REDIS_CLIENT": true, "LOG_CHANNEL": true, "SCOUT_DRIVER": true,
}

var line = regexp.MustCompile(`^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$`)

// Filter returns an env file containing only allowlisted keys, and how many
// other keys were dropped. Values are copied as written (they are driver names).
func Filter(content []byte) ([]byte, int) {
	kept := map[string]string{}
	dropped := 0
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := line.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if !Allowed[m[1]] {
			dropped++
			continue
		}
		value := unquote(m[2])
		if value != "" && !strings.EqualFold(value, "null") && safeValue(value) {
			kept[m[1]] = value
		}
	}
	keys := make([]string, 0, len(kept))
	for k := range kept {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	out.WriteString("# Written by mig-collector: only the driver settings from the original file.\n")
	for _, k := range keys {
		out.WriteString(k + "=" + kept[k] + "\n")
	}
	return out.Bytes(), dropped
}

func unquote(raw string) string {
	if raw != "" && (raw[0] == '\'' || raw[0] == '"') {
		if end := strings.IndexByte(raw[1:], raw[0]); end >= 0 {
			return raw[1 : end+1]
		}
		return raw[1:]
	}
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

// A driver or environment name: short, no spaces, no URL or credentials.
var driverName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

func safeValue(v string) bool { return driverName.MatchString(v) }
