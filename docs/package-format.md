# Package format: `mig.collector.package` 1.0.0

The collector produces one gzipped tar archive (media type
`application/vnd.mig.collector-package+gzip`). It is a public contract
between this collector and MigrateIntel's intake:
- **Minor version:** adding fields bumps it.
- **Major version:** anything else bumps it.

## Entries, in archive order

| Entry | Content |
|---|---|
| `source/<path>` | Each collected application file, at its path relative to the application folder. Secrets are masked. `.env*` files (other than `.env.example`) are replaced by their allowlisted driver settings. |
| `server/files/<absolute path>` | Server configuration files, for example `server/files/etc/nginx/sites-available/app`. Secrets are masked. |
| `server.json` | Server facts (below). Absent with `--no-server`. |
| `manifest.json` | The manifest (below). Always the last entry. |

Entries are regular files with mode 0644, no owner, and zero modification
time. Given the same input and creation time, the archive is byte-identical.

## `manifest.json`

```json
{
  "format": "mig.collector.package",
  "format_version": "1.0.0",
  "collector": {"version": "v1.0.0", "go": "go1.27.3", "os": "linux", "arch": "amd64"},
  "created_at": "2026-10-29T12:00:00Z",
  "application": "your-app",
  "files": [
    {"path": "composer.json", "stored": "source/composer.json", "kind": "source",
     "size": 1234, "sha256": "…", "redactions": 0},
    {"path": ".env", "stored": "source/.env", "kind": "env",
     "size": 80, "sha256": "…", "redactions": 0, "env_keys_dropped": 41}
  ],
  "server_files": [
    {"path": "/etc/nginx/sites-available/app", "stored": "server/files/etc/nginx/sites-available/app",
     "kind": "server-config", "size": 512, "sha256": "…", "redactions": 1}
  ],
  "skipped": [{"path": "public/index-link.php", "reason": "symbolic link (not followed)"}],
  "excluded_dirs": ["node_modules", "storage", "vendor"],
  "not_collected": {".png": 120, ".sql": 1},
  "totals": {"files": 812, "server_files": 6, "bytes": 4194304, "redactions": 9, "env_keys_dropped": 41}
}
```

- `size` and `sha256` describe the stored (masked) bytes.
- `application` is the folder's name only. The server's full path is not sent.
- `skipped` lists files that were found and not sent: links, special files,
  binary files, files that are too large or unreadable, and files after the
  collection limit.
- `not_collected` counts files the analysis doesn't use, by extension. Their
  names are not sent.

## `server.json`

```json
{
  "os": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.3 LTS"},
  "kernel": "6.8.0-79-generic",
  "arch": "amd64",
  "cpus": 4,
  "memory_bytes": 8192000000,
  "commands": {
    "php": {"args": ["php", "-v"], "output": "PHP 8.3.6 (cli) …"},
    "crontab": {"args": ["crontab", "-l"], "output": "* * * * * cd /var/www/app && php artisan schedule:run"}
  },
  "php_modules": ["Core", "mbstring", "pdo_mysql"],
  "php_ini": {"memory_limit": "512M", "opcache.enable": "1"},
  "config_files": [{"path": "/etc/nginx/sites-available/app", "size": 512}],
  "notes": ["/etc/php/8.3/fpm/pool.d/www.conf: not readable without more privileges, not included"]
}
```

Command output is masked like files. A program that is not installed is
simply absent.

## Upload

`POST https://migrateintel.com/api/collector/v1/packages`

| Header | Value |
|---|---|
| `Authorization` | `Bearer <one-time project key>` |
| `Content-Type` | `application/vnd.mig.collector-package+gzip` |
| `X-Mig-Package-Sha256` | SHA-256 of the body, hex |
| `User-Agent` | `mig-collector/<version>` |

- **Success:** `201` with `{"package_id": "…", "project_url": "…"}`.
- **Errors:** a JSON body `{"code": "…", "message": "…"}`. The collector shows
  the `message` to the user.
- **Redirects:** never followed.

The intake treats every package as untrusted input. It quarantines the
package, checks hashes and limits, and runs the preflight (SRS §9.3) before
any analysis.
