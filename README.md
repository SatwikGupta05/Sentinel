# 🛡️ Sentinel - Supply Chain Security Guardian

**Catch malicious npm packages before they destroy your project.**

[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/Node-18%2B-brightgreen?style=flat-square)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue?style=flat-square)](https://www.typescriptlang.org)
[![Status](https://img.shields.io/badge/Status-Alpha-orange?style=flat-square)](/)

---

## 🚀 What is Sentinel?

Sentinel is a **zero-trust security scanner** that analyzes npm dependencies **before installation** using 4 automated security checks (including AI) to block malicious packages and explain verdicts to developers.

Unlike traditional security tools that scan *after* compromise, Sentinel protects you **before anything runs**.

### Real Impact: Would Have Stopped These Attacks

- ✅ **Shai-Hulud Worm** (Sep 2025) - 500+ packages poisoned, stole cloud credentials
- ✅ **Axios Hijacking** (Mar 2026) - 100M downloads/week, data exfiltration trojan
- ✅ **Ledger Connect Kit** (Dec 2023) - $600K in crypto stolen via transaction hijacking
- ✅ **Qix/Phishing Shockwave** (Sep 2025) - Wallet-draining malware in chalk, debug, strip-ansi

---

## ✨ Key Features

| Feature | Benefit |
|---------|---------|
| **🔴 GitHub Action** | Scan every PR that changes dependencies |
| **🟢 CLI Tool** | `npx sentinel check-all` - scan before you install |
| **🔍 4 Security Checks** | Script analysis, code analysis, maintainer reputation, AI reasoning |
| **🚫 Auto-Blocking** | CI fails if packages are flagged as dangerous |
| **📊 Flexible Database** | SQLite (dev) or Supabase (production) |
| **🤖 AI-Powered** | Google Gemini explains *why* it blocked |
| **⚡ Fast** | Scans complete in 2-5 seconds |
| **🆓 Free** | Open source + free tier for all checks |

---

## 🔍 How It Works: 4 Security Checks

When Sentinel scans a package, it performs **4 automated checks**:

### 1️⃣ Script Diff Analysis
**Detects:** Malicious install scripts, obfuscated code, external downloads
- ❌ `curl | bash` patterns
- ❌ Suspicious `process.env` access
- ❌ Cryptocurrency mining operations
- ❌ Hidden command execution

### 2️⃣ Code Analysis
**Detects:** Data theft, credential exfiltration, suspicious patterns
- ❌ API key access (`process.env.API_KEY`, `.aws/credentials`)
- ❌ Clipboard hijacking (crypto address swapping)
- ❌ Unauthorized HTTP requests to external domains
- ❌ Obfuscated crypto operations

### 3️⃣ Author Reputation
**Detects:** Account compromises, suspicious patterns, untrusted maintainers
- ❌ New accounts (less than 1 month old)
- ❌ Sudden activity spike after dormancy
- ❌ Multiple packages published in short timeframe
- ❌ Missing security best practices (no 2FA)

### 4️⃣ AI Analysis (Google Gemini)
**Detects:** Complex attack patterns, context-aware reasoning
- ✓ Aggregates all 3 checks above
- ✓ Generates human-readable explanations
- ✓ Considers context (major version bumps, legitimate patterns)
- ✓ Outputs final verdict + confidence score (0-100%)

---

## 🎯 Two Ways to Use Sentinel

### For Teams: GitHub Action on Pull Requests

When a team member raises a PR that updates dependencies, Sentinel automatically scans them.

**How it works:**
```
1. Dev raises PR with dependency changes
   ↓
2. GitHub Action automatically triggers
   ↓
3. Sentinel scans all affected packages (2-5 seconds)
   ↓
4. Posts verdict as a PR comment
   ↓
5. If BLOCK: Merge is blocked (CI fails)
   If WARN: Team reviews before merging
   If PASS: Ready to merge
```

**Example PR Comment:**
```
🛡️ Sentinel Security Scan: PASS

Confidence Score: 98%

What Sentinel Checked:
1. ✓ Script Diff - No malicious install scripts
2. ✓ Code Analysis - No data exfiltration patterns
3. ✓ Author Reputation - Established maintainer (npm since 2014)
4. ✓ AI Analysis - All signals green

Verdict: Safe to merge ✅

View full scan report → [dashboard link]
```

**Setup (one-time):**
```yaml
# .github/workflows/sentinel.yml
name: Sentinel Security Scan

on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'yarn.lock'

permissions:
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: sentinel-security/sentinel-action@v1
        with:
          api-url: 'https://api.sentinel.dev'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

### For Solo Devs: CLI Before npm install

Run a complete security audit **before installing anything**.

**How it works:**
```
1. Developer clones repo or starts new project
   ↓
2. Runs: npx sentinel check-all
   ↓
3. Sentinel scans all dependencies (2-5 seconds)
   ↓
4. Shows verdict + next steps in terminal
   ↓
5. If BLOCK: Remove the package
   If WARN: Review/update the package
   If PASS: Proceed with npm install
```

**Example Terminal Output:**
```
🛡️  Sentinel Security Scan

Analyzing 47 packages from package.json...

Summary:
✅ PASS: 45 packages
⚠️  WARN: 1 package
🚫 BLOCK: 1 package

Verdict: ⛔ BLOCKED - Cannot proceed safely

Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ PASS (45 packages):
  ✓ react@18.2.0 (98% confidence)
  ✓ lodash@4.17.21 (99% confidence)
  ✓ express@4.18.2 (96% confidence)
  ... [42 more]

⚠️  WARN (1 package):
  ⚠️  some-old-lib@2.0.0 (68% confidence)
     • Author inactive 18 months
     • Recommend upgrading to v3.0.0
     View full report: sentinel.dev/pkg/some-old-lib

🚫 BLOCK (1 package):
  🚫 sketchy-crypto-lib@1.0.0 (CRITICAL - 8% confidence)
     • Account created 1 week ago
     • Published 50 packages in 24 hours
     • Install script contains obfuscated code
     REMOVE IMMEDIATELY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Next steps:
1. ❌ Remove: sketchy-crypto-lib from package.json
2. ⚠️  Update: some-old-lib to v3.0.0
3. ✅ Then run: npm install
```

**Usage:**
```bash
# Clone any repo
$ git clone https://github.com/someone/project
$ cd project

# First command: scan all dependencies
$ npx sentinel check-all

# Review results, then install
$ npm install
$ npm start
```

**Supported Ecosystems:**
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock` *(planned)*
- Ruby: `Gemfile.lock` *(planned)*

---

## 📊 The Verdict System

All scans return **one of three verdicts**:

### ✅ PASS (90%+ confidence)
- All 4 checks passed
- Zero security concerns detected
- **Action:** Safe to install immediately

### ⚠️ WARN (40-90% confidence)
- Mixed signals detected
- Could be legitimate edge case or suspicious pattern
- **Action:** Review before proceeding
- Examples:
  - Package reads env vars (might be intentional)
  - Author less established (but no other red flags)
  - Major version bump with code changes (expected)

### 🚫 BLOCK (<40% confidence)
- High-risk signals detected
- Likely malicious or compromised
- **Action:** Cannot proceed (CI fails for teams, exits 1 for solo devs)
- Examples:
  - Install script with obvious data exfiltration
  - New account with suspicious activity spike
  - Code matching known malware signatures
  - Obfuscated credential access

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         Two Entry Points                │
└─────────────────────────────────────────┘
      │                         │
      │                         │
  GitHub Action          CLI Tool
  (Teams on PRs)    (Solo Devs)
      │                         │
      └──────────┬──────────────┘
                 │
                 ▼
    ┌────────────────────────────┐
    │  Sentinel Backend API      │
    │  (Orchestrates Checks)     │
    └────────────────────────────┘
      │      │      │       │
      ▼      ▼      ▼       ▼
   Script  Code   Author   Gemini
   Diff    Analysis  Rep    AI
   Check   Check    Check   Analysis
      │      │      │       │
      └──────┴──────┴───────┘
              │
              ▼
    ┌────────────────────────────┐
    │  Verdict + Confidence      │
    │  PASS / WARN / BLOCK       │
    └────────────────────────────┘
         │            │
         │            │
    GitHub PR     CLI Terminal
    Comment       Output
```

---

## ⚡ Quick Start

### For Teams (GitHub Action)

1. Add `.github/workflows/sentinel.yml` to your repo (see example above)
2. Create a PR with package changes
3. Sentinel automatically scans and comments

### For Solo Devs (CLI)

```bash
# Scan any project
npx sentinel check-all

# Check specific file
npx sentinel check-all package.json
npx sentinel check-all requirements.txt
npx sentinel check-all yarn.lock
```

### Local Development

```bash
# Clone repo
git clone https://github.com/SatwikGupta05/Sentinel.git
cd sentinel

# Install dependencies
npm install

# Copy environment file
cp .env.example .env
# Edit .env with your API keys

# Initialize database
npm run db:init

# Start API server
npm run dev

# In another terminal, start CLI
npx sentinel check-all
```

---

## 🗄️ Database Selection Guide

Choose the right database for your use case:

| Aspect | SQLite | Supabase |
|--------|--------|----------|
| **Best for** | Local dev, testing | Production, teams |
| **Setup time** | 30 seconds | 5 minutes |
| **Backups** | Manual | Automatic daily |
| **Team access** | ❌ None | ✅ Web dashboard |
| **Free tier** | ∞ | 500MB + 1GB transfer |
| **Scaling** | Up to 100K rows | ∞ |
| **Cost at scale** | $0 | ~$25/mo |

### SQLite (Development)
Perfect for local testing, no setup needed:
```env
DB_TYPE=sqlite
DB_PATH=./data/sentinel.db
```

### Supabase (Production)
Cloud-hosted PostgreSQL with automatic backups:
```env
DB_TYPE=supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your_service_role_key
```

See [SENTINEL_COMPLETE.md](SENTINEL_COMPLETE.md) for detailed setup instructions.

---

## ⚙️ Configuration

All configuration via `.env`:

```env
# Database
DB_TYPE=sqlite                    # or supabase
DB_PATH=./data/sentinel.db        # SQLite only

# API Configuration
SENTINEL_API_KEY=sk_sentinel_...  # For API authentication
API_PORT=5000
NODE_ENV=development              # or production

# Google Gemini (AI Analysis)
GEMINI_API_KEY=your_api_key       # Free tier available
GEMINI_MODEL=gemini-2.5-flash     # Fast, free tier

# GitHub Integration
GITHUB_TOKEN=ghp_your_token       # For GitHub Action
```

**Get API keys:**
- Gemini: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
- GitHub: [github.com/settings/tokens](https://github.com/settings/tokens)
- Supabase: [supabase.com](https://supabase.com)

---

## 📡 API Reference

### POST /api/scans
Trigger a security scan for packages.

```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_sentinel_..." \
  -d '{
    "repo": "user/project",
    "pr_number": 42,
    "pr_author": "alice",
    "branch": "feature/upgrade-deps",
    "packages": {
      "lodash": {"old": "4.17.20", "new": "4.17.21"},
      "react": {"old": "17.0.0", "new": "18.0.0"}
    }'
```

**Response (200 OK):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "PASS",
  "confidence_score": 95,
  "timestamp": "2025-05-24T10:30:00Z",
  "signals": [
    {
      "check_type": "script_diff",
      "severity": "info",
      "message": "No install scripts detected"
    },
    {
      "check_type": "code_analysis",
      "severity": "info",
      "message": "No suspicious patterns found"
    },
    {
      "check_type": "author_reputation",
      "severity": "info",
      "message": "Author is well-established"
    },
    {
      "check_type": "ai_analysis",
      "severity": "info",
      "message": "All checks passed, safe to install"
    }
  ]
}
```

### GET /api/scans
List recent scans with filtering.

```bash
# Get last 50 scans
curl http://localhost:5000/api/scans \
  -H "X-API-Key: sk_sentinel_..."

# Filter by repository and verdict
curl "http://localhost:5000/api/scans?repo=user/project&verdict=BLOCK" \
  -H "X-API-Key: sk_sentinel_..."
```

### GET /api/scans/:scan_id
Get detailed scan results.

```bash
curl http://localhost:5000/api/scans/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: sk_sentinel_..."
```

---

## 🛠️ Development

### Project Structure

```
sentinel/
├── src/
│   ├── api/              # Express routes & auth
│   ├── cli/              # CLI interface
│   ├── db/               # Database layer (SQLite/Supabase)
│   ├── scanner/          # Core security checks
│   │   ├── checks/       # 4 security check modules
│   │   └── types.ts      # Type definitions
│   ├── parsers/          # Package file parsers
│   └── server.ts         # Main server entry
├── dist/                 # Compiled TypeScript
├── data/                 # SQLite database (dev)
├── .env.example          # Environment template
├── package.json          # Dependencies
└── tsconfig.json         # TypeScript config
```

### Scripts

```bash
npm run dev              # Start API server (dev mode)
npm run build            # Compile TypeScript
npm run start            # Run compiled server
npm run db:init          # Initialize database
npm run db:reset         # Reset database
npm run lint             # Lint code
npm run type-check       # Check TypeScript types
```

---

## 🐛 Troubleshooting

### SQLite Issues

**"SQLITE_CANTOPEN"**
```bash
mkdir -p data
npm run db:init
```

**"Database is locked"**
- Only one API instance can write at a time
- Use Supabase for concurrent access


## 📈 Best Practices

### Security
- Never commit `.env` files to Git
- Use GitHub Secrets for CI/CD
- Rotate API keys every 90 days
- Use Supabase's Service Role Key (not Anon Key)

### Performance
- Cache npm registry lookups (24 hours)
- Scan in parallel for multiple packages
- Monitor database growth (1MB per 1,000 scans)

### Monitoring
- Track scan latency (target: <5 seconds)
- Monitor API error rates
- Review blocked packages weekly
- Keep database backups

---

## ❓ FAQ

**Q: Does Sentinel send my code to Google?**
A: No. Only package names, versions, and npm metadata are sent to Gemini. Your source code stays local.

**Q: Can I migrate from SQLite to Supabase?**
A: Yes, export SQLite data and import to Supabase (script included).

**Q: Can I use my own database?**
A: Currently SQLite and Supabase are supported. Database adapters are welcome!

**Q: How do I disable the AI check?**
A: Set `GEMINI_API_KEY=` (empty). Sentinel will use 3 checks instead of 4.

**Q: Can Sentinel scan Python/Ruby packages?**
A: Support is planned for Phase 2. Currently focused on npm.

---

## 📊 Success Metrics

### For Teams
- Number of PRs blocked (high-risk packages prevented)
- Scan latency (target: <5 seconds)
- GitHub Action adoption rate

### For Solo Devs
- CLI downloads/week
- Packages caught before installation
- User feedback and retention

---

## 🗺️ Roadmap

### Current (Phase 1)
- ✅ GitHub Action for teams
- ✅ CLI tool for solo devs
- ✅ 4 automated security checks
- ✅ SQLite + Supabase support
- ✅ API authentication

### Coming Soon (Phase 2)
- 🔜 VS Code extension
- 🔜 npm install hooks
- 🔜 Git pre-commit hooks
- 🔜 Python/Ruby support
- 🔜 Slack/Discord notifications

### Future (Phase 3)
- 📅 Organization management
- 📅 Custom security policies
- 📅 Threat intelligence feeds
- 📅 SBOM export
- 📅 Enterprise compliance features

---

## 🤝 Contributing

We welcome contributions! Areas we need help:

1. **Security Heuristics** - Better patterns for detecting supply chain attacks
2. **Database Adapters** - PostgreSQL, MySQL support
3. **Package Managers** - Python, Ruby, Go, Rust parsers
4. **Integrations** - Slack, Discord, PagerDuty, SIEM tools
5. **Documentation** - Tutorials, blog posts, video guides


## 📄 License

MIT © 2025 Sentinel Team

---

## 🎯 Our Mission

**Sentinel exists to make the JavaScript ecosystem safe by default.**

No more hoping packages are safe.  
No more learning about compromises weeks after installation.  
No more supply chain attacks that could have been prevented.

**Check before you install. Stay secure. Sleep better.** 🛡️

---

**Built with ❤️ for JavaScript security.**

[⭐ Star us on GitHub](https://github.com/yourusername/sentinel) | [🐦 Follow on Twitter](https://twitter.com/sentinel_security) | [📢 Read our Blog](https://sentinel.dev/blog)