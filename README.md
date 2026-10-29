# MigrateIntel collector

`mig-collector` reads a PHP application and the server it runs on, and sends
what the [MigrateIntel](https://migrateintel.com) migration analysis needs to
your project. It runs once and leaves nothing installed. Nothing stays running,
and MigrateIntel never logs in to your server.

It is open source under the [Apache License 2.0](LICENSE) so you can read
exactly what it does, build it yourself, and check that the binary you run is
the one built from this source. The analysis engine itself runs on MigrateIntel's
servers and is not part of this repository.

## What it does

1. **Reads the application folder in place.** It never changes a file and needs no admin rights.
   - **What it reads:** the application's own code and configuration (PHP,
     Blade, JavaScript, `composer.json`/`composer.lock`, `package.json`,
     Docker, CI and web-server configuration).
   - **What it never reads:**
     - `vendor/`, `node_modules/`, `storage/` (uploads, logs, sessions,
       caches), `public/uploads`, `public/storage`, `.git`;
     - media, databases and other data files;
     - credential files (`auth.json`, `.npmrc`, `.netrc`, `.pgpass`,
       `.my.cnf`).
   - **Links:** symbolic links are never followed. Only regular files are
     opened, and each must still be the same file it was when it was listed.
2. **Records server facts:**
   - OS, kernel, CPU and memory;
   - PHP version, extensions and a few `php.ini` settings;
   - Composer, Node, npm, nginx/Apache, MariaDB/MySQL/PostgreSQL, Redis and
     Supervisor versions;
   - the web-server, PHP-FPM, Supervisor, systemd and cron configuration
     files under `/etc`;
   - your own crontab.

   These come from version commands run with fixed arguments and no shell.
   Anything it can't read without more privileges is noted and skipped.
3. **Masks secrets before anything is packaged** (SRS §16):
   - **`.env` files** are never sent. They are replaced by a file holding only
     the driver settings, such as `DB_CONNECTION`, `QUEUE_CONNECTION` and
     `CACHE_STORE`.
   - **Passwords, keys and tokens** in code and configuration are replaced by
     `[REDACTED]`. These are found by their name (`DB_PASSWORD`,
     `'secret' => …`, `fastcgi_param APP_KEY …`) and by their format (AWS,
     GitHub, Stripe, Slack, Google and OpenAI keys, JWTs, private keys,
     passwords in URLs).
4. **Sends the package** over HTTPS to your MigrateIntel project, or writes it
   to a file so you can decide.

## Use it

On your project page, copy the command. It looks like this:

```bash
curl -fsSL https://migrateintel.com/collect.sh | MIG_COLLECTOR_KEY=<one-time key> sh -s -- /var/www/your-app
```

[`scripts/install.sh`](scripts/install.sh) runs the collector in a few steps:

1. It downloads the binary for your CPU (Linux amd64 or arm64) from this
   repository's releases.
2. It checks the binary against the published SHA-256 checksums. If `cosign`
   is installed, it also checks the release's Sigstore signature.
3. It runs the binary once.
4. It deletes the binary and its temporary folder, whatever happened.

To see exactly what would be sent first, without sending anything:

```bash
curl -fsSL https://migrateintel.com/collect.sh | sh -s -- preview /var/www/your-app
```

Or download a binary from [Releases](../../releases) and run it yourself:

```bash
mig-collector preview /var/www/your-app          # list every file and fact; sends nothing
mig-collector preview --json /var/www/your-app   # the same, as JSON
mig-collector collect --out app.tar.gz /var/www/your-app   # write the package here
MIG_COLLECTOR_KEY=<key> mig-collector upload /var/www/your-app
```

Run it on a staging copy first if you prefer. `--no-server` leaves out the
server facts and configuration.

The collector sends only to `migrateintel.com` (or `migrateintel.net` for
MigrateIntel's staging), over HTTPS, and never follows redirects.

| Exit code | Meaning |
|---|---|
| 0 | Done |
| 1 | Something failed (the message says what) |
| 2 | Usage: wrong folder (no `composer.json`), missing or malformed key, endpoint that is not MigrateIntel |

## Verify a release

Every release is built by [`release.yml`](.github/workflows/release.yml) from
its tag, with Go 1.27.3. The release publishes:
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`, a keyless Sigstore signature tied to that
  workflow and tag.

To verify:

```bash
sha256sum -c --ignore-missing SHA256SUMS
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Application-Migration-Intelligence/collector/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
```

Builds are reproducible: with Go 1.27.3, the same tag gives byte-identical
binaries.

```bash
git checkout v1.0.0
make release VERSION=v1.0.0
cat dist/SHA256SUMS   # matches the release's SHA256SUMS
```

## The package

A gzipped tar archive (`mig.collector.package` 1.0.0) holding:
- `source/…`: the collected files, with secrets masked;
- `server/files/…`: the server's configuration files, with secrets masked;
- `server.json`: the server facts;
- `manifest.json`: every file sent, with its SHA-256 and how many values were
  masked, plus everything left out and why.

The full format is in [docs/package-format.md](docs/package-format.md).

## Develop

Go 1.24 or newer, standard library only.

```bash
make test lint
make build VERSION=dev && ./dist/mig-collector preview /path/to/app
```

Report security issues as described in [SECURITY.md](SECURITY.md).
