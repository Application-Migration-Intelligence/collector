# Security

Please report vulnerabilities privately to **security@migrateintel.com**, or
through GitHub's private vulnerability reporting on this repository. Don't
open a public issue. We acknowledge reports within two business days.

Especially relevant:
- anything that sends a secret the collector should have masked;
- reading outside the application folder or the listed server files;
- following a symbolic link;
- sending anywhere other than MigrateIntel;
- anything that lets a tampered binary pass the checksum or signature check.
