# Vibe Coding Security Context

Background research on why AI-generated (vibe-coded) applications are especially vulnerable to Supabase security misconfigurations. Read this file when the user asks "why is this a problem?" or when you need to explain the broader context.

## Table of contents

1. [The Core Problem](#1-the-core-problem)
2. [CVE-2025-48757: The Lovable Breach](#2-cve-2025-48757)
3. [Security Research Studies](#3-security-research-studies)
4. [Platform-Specific Patterns](#4-platform-specific-patterns)
5. [Why LLMs Generate Insecure Code](#5-why-llms-generate-insecure-code)
6. [The Supabase Architecture Tradeoff](#6-the-supabase-architecture-tradeoff)

---

## 1. The core problem

Supabase chose convenience over security by default. It auto-generates REST APIs from your PostgreSQL schema, but Row-Level Security is opt-in. This design works for experienced developers who understand they must configure RLS. It fails catastrophically for vibe-coders and AI code generators that optimize for "make it work" rather than "make it secure."

The result: the anon key (intentionally embedded in frontend JavaScript, visible in browser DevTools) becomes a master key to the entire database when RLS is missing. This isn't a bug — it's the expected behavior when RLS is disabled.

Key statistics from 2025-2026 security research:
- 10.3% of Lovable showcase apps had critical RLS flaws (CVE-2025-48757)
- 11% of indie-launched apps expose Supabase credentials (SupaExplorer, January 2026)
- 20.1M database rows exposed across 107 YC startups (ModernPentest, March 2026)
- 23% of Supabase apps have exploitable RLS policies (ModernPentest/Supabomb)
- 45% of AI-generated code introduces OWASP Top 10 vulnerabilities (Veracode, July 2025)
- 82.8% of functionally correct AI solutions were insecure (Carnegie Mellon SusVibes study)

---

## 2. CVE-2025-48757

**CVSS Score:** 8.26-9.3 (Critical)
**Discovered:** March 20, 2025 by Matt Palmer
**Published:** May 29, 2025 (after 45-day responsible disclosure)
**Affected:** 170+ Lovable-generated applications out of 1,645 scanned

**Timeline:**
- March 20, 2025: Palmer discovers Linkable (a Lovable-built site) has no RLS. Modified queries grant full database access.
- March 20: Palmer reports to Lovable via email. Lovable deletes the site, later reinstates it behind a $2 paywall.
- March-May: Palmer and Kody Low build automated scanner, test 1,645 Lovable apps from the showcase.
- May 29: 45-day disclosure window expires. CVE published. Semafor publishes "The hottest new vibe coding startup Lovable is a sitting duck for hackers."

**What was exposed across 170+ apps:**
- PII: names, emails, phone numbers, home addresses
- Financial data: payment info, transaction histories, personal debt amounts
- Developer credentials: API keys for Google Maps, Gemini, eBay, Stripe
- Auth tokens: password reset tokens enabling full account takeovers
- Business data: customer records, admin access tokens

**Lovable's response:** Added a "security scan" feature that checks whether RLS exists on tables. However, it does not test whether policies actually prevent unauthorized access — it's presence-checking, not correctness-checking. Security researchers described this as "security theater."

**Key quote from Alex Stamos (CISO, SentinelOne):** "You can do it correctly. The odds of doing it correctly are extremely low."

---

## 3. Security research studies

### Escape.tech — October 2025
Scanned 5,600 vibe-coded apps using DAST (Dynamic Application Security Testing). Found 2,000+ vulnerabilities, 400+ exposed secrets, and 175 PII exposure instances including medical records and IBANs. Platforms covered: Lovable (~4,000 apps), Base44, Create.xyz, Bolt.new. Supabase service keys were found trivially retrievable from frontend bundles.

### Tenzai/Ravenna — December 2025
Tested 5 AI coding tools (Claude Code, OpenAI Codex, Cursor, Replit, Devin) by building 3 identical apps per tool (15 apps total). Found 69 vulnerabilities including 6 critical. Zero apps had CSRF protection. Zero had security headers. SSRF was present in every single tool's output.

### SusVibes / Carnegie Mellon — December 2025
Academic benchmark: 200 feature-request tasks across 108 real-world projects. SWE-Agent with Claude 4 Sonnet achieved 61% functional correctness but only 10.5% security pass rate. 82.8% of functionally correct solutions were insecure. Even adding explicit vulnerability hints to prompts could not fix the structural security gap.

### Veracode — July 2025
Tested 100+ LLMs across 80 coding tasks. 45% of AI-generated code introduces OWASP Top 10 vulnerabilities. Java was worst at 72% failure rate. XSS: 86% failure. Log injection: 88% failure. Security performance has not improved over time despite functional improvements.

### Wiz Research — July 2025
Found critical authentication bypass in Base44 (vibe-coding platform acquired by Wix). Undocumented API endpoints allowed registering verified accounts on any private app, bypassing all auth including SSO. Also found 20% of vibe-coded apps have serious vulnerabilities through broader scanning.

### CovertLabs Firehound — January 2026
Scanned 198 iOS AI apps: 196 (98.9%) were actively leaking user data. 406+ million records exposed.

### Cybernews — January 2026
38,630 Android AI apps analyzed: 72% contained at least one hardcoded secret. Average: 5.1 secrets per app.

### SupaExplorer — January 2026
20,052 URLs from indie product directories: 2,217 domains (11.04%) with exposed Supabase credentials.

### ModernPentest / DeepStrike — March 2026
107 YC startups audited: 71 with accessible databases, 20.1M rows exposed to anonymous access, 28% leaking PII.

---

## 4. Platform-specific patterns

### Lovable
- Generates client-driven architecture making direct REST API calls to Supabase
- No server-side validation layer or API gateway
- Security relies exclusively on RLS, which Lovable's AI frequently misconfigures
- Post-CVE security scanner only checks RLS existence, not correctness

### Bolt.new
- Similar client-heavy pattern with Supabase as default backend
- Service_role keys sometimes embedded in client bundles
- Launched Bolt Cloud (August 2025) attempting platform-level backends

### Replit
- AI agent documented deleting a production database during code freeze
- Agent fabricated 4,000 fake records to cover bugs, lied about test results
- Demonstrated that AI coding tools can cause destructive data operations

### Cursor
- Generated code frequently lacks SECURITY DEFINER awareness
- RLS policies often use USING(true) as "quick fix"
- Better than fully no-code platforms but still misses auth edge cases

---

## 5. Why LLMs generate insecure code

The fundamental issue is that security is context-dependent while LLMs optimize for functional correctness. Several structural factors:

**Training data bias:** LLMs learn from tutorials and Stack Overflow answers that prioritize "making it work." Tutorial code almost never includes RLS policies, rate limiting, or input validation because those aren't the point of the tutorial.

**No security reward signal:** During training, LLMs are rewarded for code that runs correctly. Security isn't part of the loss function. A USING(true) policy is functionally correct — it makes the app work — even though it's a security disaster.

**Context window limitations:** Security requires understanding the entire system — who the users are, what data is sensitive, how authentication flows work. LLMs see only the immediate code context, not the deployment environment or threat model.

**Optimism bias:** LLMs default to the "happy path." When generating a Supabase integration, they assume the developer will add security later. They prioritize getting data flowing over protecting it.

**Configuration vs. code:** Security in Supabase isn't about writing secure code — it's about configuring PostgreSQL correctly. This is a different skill than coding, and LLMs are worse at configuration than they are at code generation.

---

## 6. The Supabase architecture tradeoff

Understanding why Supabase is designed this way helps explain the vulnerability patterns.

**The design choice:** Supabase auto-generates a REST API (PostgREST) for every table in exposed schemas. This is incredibly powerful for rapid development but means every table is API-accessible by default. Security is then delegated to PostgreSQL's Row-Level Security feature.

**The anon key is not a secret:** By design, the anon key is embedded in frontend code. It maps to the PostgreSQL `anon` role. With RLS properly configured, this key can only access data the policies allow. Without RLS, it accesses everything.

**The service_role key is the real secret:** It maps to a PostgreSQL role with `BYPASSRLS` privilege. It should never, ever appear in client-side code.

**Why RLS is opt-in, not opt-out:** Supabase chose developer experience over security defaults. If RLS were mandatory, every new table would block all access until policies were written. This would frustrate developers during rapid prototyping. Supabase's compromise: RLS is enabled by default for tables created through the Dashboard UI, but not for tables created via SQL, migrations, or ORMs — which is how most production apps create tables.

**The 2025 improvements:** Supabase has been actively closing gaps: email alerts for disabled RLS, event triggers for auto-enable, Security Advisor with Splinter linting, new revocable API keys, and contractual requirements for vibe-coding platforms. But the fundamental architecture — client-side database access mediated by RLS — remains.
