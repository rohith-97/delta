# delta

A security audit platform — built vulnerable, attacked with custom tools, then hardened.

Delta is not just a collection of security tools. It's a complete attack-and-defend system: a web server with real vulnerabilities, custom offensive tools that exploit them, and secure implementations that fix each one.

## What it demonstrates

| Component | Attack | Defense |
|-----------|--------|---------|
| Authentication | Brute force simulator | bcrypt + account lockout |
| XSS | 8-payload scanner | HTML sanitization + CSP headers |
| File upload | Dangerous extension bypass | MIME detection + whitelist |
| Port scanning | Concurrent TCP scanner | — |
| Login tracking | — | Activity log + suspicious IP detection |

## Architecture
delta/
├── cmd/server          # main web server (Go)
├── cmd/scanner         # port scanner CLI
├── internal/auth       # JWT auth + bcrypt + lockout
├── internal/tracker    # login activity tracking
├── internal/upload     # secure file upload
├── internal/vuln       # intentionally vulnerable endpoints
├── attacks/bruteforce  # password attack simulator
└── attacks/xss         # XSS payload scanner

## Quick start

```bash
# start PostgreSQL
sudo systemctl start postgresql

# run the server
go run cmd/server/main.go
```

Server starts at `http://localhost:9090`.

## Attack demos

### 1. Password brute force

```bash
# register a user
curl -X POST http://localhost:9090/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "target", "email": "target@test.com", "password": "securepass123"}'

# run the attack
go build ./attacks/bruteforce/
./bruteforce -username target -concurrency 2
```

Output:
[✓ FOUND] password=securepass123 token=eyJhbGciOiJI...
[LOCKED] password=... → account locked
Total attempts : 17
Successful     : 1
Locked out     : 10

Account locks after 5 failed attempts within 15 minutes.

### 2. XSS scanning

```bash
go build ./attacks/xss/

# attack the vulnerable endpoint
./xss -target http://localhost:9090 -path /vuln/xss

# attack the secure endpoint
./xss -target http://localhost:9090 -path /secure/xss
```

Output:
Vulnerable endpoint: 8/8 payloads reflected
Secure endpoint:     0/8 payloads reflected

### 3. Port scanning

```bash
go build ./cmd/scanner/
./scanner -host localhost -start 1 -end 10000 -concurrency 500
```

Output:
Scanned 10000 ports in 367ms
PORT     SERVICE          LATENCY
5432     PostgreSQL       7ms
9090     HTTP-Alt         10ms

### 4. File upload security

```bash
TOKEN=<your_jwt_token>

# blocked: dangerous extension
curl -X POST http://localhost:9090/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.php"
# → {"error":"dangerous file type detected"}

# allowed: safe file
curl -X POST http://localhost:9090/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@document.pdf"
# → {"id":1,"mime_type":"application/pdf",...}
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | No | Register user |
| POST | `/auth/login` | No | Login, get JWT |
| GET | `/me` | Yes | Current user |
| GET | `/activity` | Yes | Login history |
| GET | `/activity/stats` | Yes | Login statistics |
| GET | `/suspicious` | Yes | Suspicious IPs |
| POST | `/upload` | Yes | Upload file |
| GET | `/files` | Yes | List uploads |
| GET | `/vuln/xss` | No | Vulnerable XSS endpoint |
| GET | `/secure/xss` | No | Hardened XSS endpoint |
| POST | `/vuln/xss/stored` | No | Stored XSS demo |

## Security features

**Authentication**
- Passwords hashed with bcrypt (cost 12)
- JWT tokens with 24h expiry
- Account lockout after 5 failed attempts in 15 minutes
- Minimum password length enforced

**File upload**
- MIME type detected from file content, not extension
- Whitelist of allowed types: jpeg, png, gif, webp, pdf, txt, csv
- Dangerous extensions blocked: php, exe, sh, py, asp, jsp and more
- Files renamed to `{userID}_{hash}{ext}` — no original filename preserved
- 10MB size limit

**XSS protection**
- HTML entity encoding on all user input
- Content-Security-Policy header
- X-XSS-Protection header

**Observability**
- Every login attempt logged with IP, user agent, success/failure
- Suspicious IP detection (configurable threshold)
- Full activity history per user

## Stack

Go · chi · PostgreSQL · JWT · bcrypt
