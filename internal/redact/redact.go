// Package redact masks secrets in text before anything is packaged (SRS §16).
//
// The patterns match the MigrateIntel engine's redaction
// (engine/src/mig_engine/core/redaction.py in the platform repository), so a
// value the engine would hide never leaves the server in the first place.
// Redaction is deliberately aggressive: masking a harmless value costs little,
// sending a credential costs a lot.
package redact

import (
	"regexp"
	"strings"
)

// Mask replaces every secret value.
const Mask = "[REDACTED]"

// Names that usually hold secrets, in KEY=value, 'key' => 'value' and "key": "value" forms.
const secretName = `[A-Za-z0-9_.\-]*(?:(?i)pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth|credential|salt|signing[_-]?key|dsn|app[_-]?key|webhook[_-]?key|client[_-]?secret)[A-Za-z0-9_.\-]*`

type rule struct {
	re   *regexp.Regexp
	repl func(m []string) string
}

var rules = []rule{
	// PEM private key blocks, including when truncated.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`),
		func([]string) string { return Mask }},
	// KEY=value (env files, shell) and KEY: value (YAML).
	{regexp.MustCompile(`(?im)^(\s*(?:export\s+)?` + secretName + `\s*[=:][ \t]*)(\S.*)$`),
		func(m []string) string { return m[1] + Mask }},
	// 'key' => 'literal' (PHP arrays). env('X', 'default') calls are not literals and
	// stay, and so do Laravel casts and validation rules ('password' => 'hashed').
	{regexp.MustCompile(`(?i)(['"]` + secretName + `['"]\s*=>\s*)'([^'\n]+)'`),
		func(m []string) string { return keepRule(m, "'") }},
	{regexp.MustCompile(`(?i)(['"]` + secretName + `['"]\s*=>\s*)"([^"\n]+)"`),
		func(m []string) string { return keepRule(m, `"`) }},
	// "key": "value" (JSON).
	{regexp.MustCompile(`(?i)("` + secretName + `"\s*:\s*)"((?:[^"\\\n]|\\.)+)"`),
		func(m []string) string { return m[1] + `"` + Mask + `"` }},
	// Server configuration: nginx fastcgi_param, Apache SetEnv, PHP-FPM env[...] and
	// php_value, NAME=value inside a line (systemd Environment=, supervisor
	// environment=, crontab). The engine's own redaction does not need these
	// because it only quotes the application's code.
	{regexp.MustCompile(`(?i)\b((?:fastcgi_param|SetEnv|SetEnvIf\S*|PassEnv)\s+` + secretName + `\s+)("[^"\n]*"|'[^'\n]*'|[^\s;]+)`),
		func(m []string) string { return m[1] + Mask }},
	{regexp.MustCompile(`(?im)\b((?:env|php_value|php_admin_value)\[` + secretName + `\]\s*=[ \t]*)(\S.*)$`),
		func(m []string) string { return m[1] + Mask }},
	{regexp.MustCompile(`(?i)([\s"',]` + secretName + `=)("[^"\n]*"|'[^'\n]*'|[^\s"',]+)`),
		func(m []string) string { return m[1] + Mask }},
	// Credentials inside URLs: scheme://user:password@host
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s@/]+)(@)`),
		func(m []string) string { return m[1] + Mask + m[3] }},
	// Well-known token formats.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), func([]string) string { return Mask }},
	{regexp.MustCompile(`\bbase64:[A-Za-z0-9+/]{32,}={0,2}`), func([]string) string { return Mask }},
}

// Words that are Laravel casts or validation rules, never secrets.
var ruleWords = map[string]bool{
	"hashed": true, "encrypted": true, "boolean": true, "bool": true, "datetime": true, "date": true,
	"immutable_datetime": true, "immutable_date": true, "timestamp": true, "string": true, "integer": true,
	"int": true, "float": true, "double": true, "decimal": true, "array": true, "json": true, "object": true,
	"collection": true, "required": true, "nullable": true, "sometimes": true, "confirmed": true,
	"min": true, "max": true, "between": true, "size": true, "current_password": true, "password": true,
	"different": true, "same": true, "regex": true, "bail": true, "filled": true, "present": true,
}

func keepRule(m []string, quote string) string {
	value := m[2]
	parts := strings.Split(value, "|")
	for _, part := range parts {
		head, _, _ := strings.Cut(part, ":")
		if !ruleWords[strings.ToLower(strings.TrimSpace(head))] {
			return m[1] + quote + Mask + quote
		}
	}
	return m[0]
}

// Text returns text with secrets masked, and how many values were masked.
func Text(text string) (string, int) {
	return apply(rules, text)
}

// Formats masks only well-known secret formats (keys, tokens, private keys,
// credentials in URLs), for dependency manifests and lock files, whose
// package names ("ext-tokenizer") would trip the name-based rules.
func Formats(text string) (string, int) {
	return apply(formatRules, text)
}

var formatRules []rule

func init() {
	formatRules = append([]rule{rules[0]}, rules[nameRules+1:]...)
}

// nameRules is how many rules after the private-key rule match by name.
const nameRules = 7

func apply(rs []rule, text string) (string, int) {
	total := 0
	for _, r := range rs {
		text = r.re.ReplaceAllStringFunc(text, func(match string) string {
			sub := r.re.FindStringSubmatch(match)
			if sub == nil { // cannot happen: match came from the same pattern
				return match
			}
			out := r.repl(sub)
			if out != match {
				total++
			}
			return out
		})
	}
	return text, total
}
