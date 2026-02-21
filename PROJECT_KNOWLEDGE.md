# Regulatory Alert SaaS - Project Knowledge

## Overview
AI-powered regulatory alert monitoring micro-SaaS for financial services. Monitors SEC and CFTC filings via RSS feeds and HTML scraping, generates AI summaries using Claude Haiku 4.5, delivers push notifications via webhooks, email, and Slack, and serves results through a FastAPI REST API with optional API key auth. Currently in **Founding Member Beta** (v0.10.0-beta) — all new signups receive Pro tier free during the beta period.

## Architecture

### Tech Stack
- **Python 3.11+** with `src/` layout (`src/regulatory_alerts/`)
- **SQLAlchemy 2.0** (async + sync) with Mapped/mapped_column style
- **SQLite** (default, via aiosqlite) — PostgreSQL-ready via config swap
- **Alembic** for migrations (sync engine, reads DATABASE_URL_SYNC from config)
- **FastAPI** for REST API (sync endpoints, lifespan context manager)
- **Anthropic SDK** for AI summarization (Claude Haiku 4.5)
- **APScheduler** for background periodic feed fetching
- **feedparser** for RSS/Atom parsing
- **httpx** for async HTTP with rate limiting + webhook delivery
- **Click + Rich** for CLI
- **pydantic-settings** for config (.env file)
- **tenacity** for retry logic on HTTP requests
- **smtplib** for email notifications
- **Docker + PostgreSQL** for production deployment
- **Stripe** for subscription billing (Checkout Sessions, Customer Portal, webhooks)

### Package Structure
```
config.py                          # backward-compat shim → re-exports from src/regulatory_alerts/config.py
Dockerfile                         # Python 3.12-slim, installs deps, runs uvicorn
docker-compose.yml                 # PostgreSQL 16 + API service with auto-migration
.dockerignore                      # excludes tests, .env, data, IDE files
src/regulatory_alerts/
  __init__.py                      # empty
  config.py                        # pydantic-settings: DATABASE_URL, API keys, SMTP, scheduler
  cli.py                           # Click CLI: init-db, list-feeds, fetch, serve, add-webhook, add-email, list-channels
  api.py                           # FastAPI app with auth, rate limiting, lifespan, scheduler
  dashboard.py                     # Jinja2 HTML routes (HTMX + Tailwind dashboard)
  core/
    feed_fetcher.py                # FeedFetcher + RateLimiter + FeedEntry dataclass
    document_processor.py          # Dedup + persist entries to DB (sync)
    ai_summarizer.py               # Claude API call, JSON parsing, relevance scoring
    cftc_scraper.py                # HTML scraper for CFTC press releases (3 parsing strategies with fallback, retry)
    notifier.py                    # Webhook (HTTP POST + HMAC) and email (SMTP) notification delivery + retry with exponential backoff
    scheduler.py                   # APScheduler background fetch cycle (fetch → dedup → summarize → notify → retry)
  database/
    session.py                     # Engine + session factories (async + sync, lru_cache'd), SQLite FK pragma
  models/
    __init__.py                    # Imports all models (resolves string-based SQLAlchemy relationships)
    base.py                        # DeclarativeBase + TimestampMixin
    document.py                    # FeedSource, FeedDocument
    alert.py                       # ProcessedAlert (AI-generated summary data)
    notification.py                # NotificationChannel, NotificationLog
    user.py                        # User (email, hashed_password, api_key, is_active, Stripe billing, subscribed_topics, is_founding_member, beta_enrolled_at)
    stripe_event.py                # StripeEvent (webhook idempotency)
  auth.py                          # Session-based auth: login/register/logout/account/password-reset routes, bcrypt hashing, itsdangerous tokens, rate limited
  billing.py                       # Stripe billing: checkout, portal, webhooks, tier limits, channel gating
  csrf.py                          # CSRF protection: session token generation + validation dependency
  rate_limit.py                    # Shared rate limiting: Limiter, key function, dynamic rate limit helper (used by api.py + auth.py)
  validation.py                    # Input validation: webhook URL SSRF prevention (blocks private IPs, non-HTTP schemes, DNS rebinding)
  observability.py                 # Structured logging, request middleware, scheduler metrics, error tracking
scripts/
  init_feeds.py                    # Standalone feed seeder (alternative to CLI init-db)
tests/
  conftest.py                      # Shared fixtures: in-memory SQLite, seed data
  test_api.py                      # 18 API integration tests (health, updates, channels, auth, rate limiting)
  test_dashboard.py                # 19 dashboard tests (HTML routes, HTMX fragments, channel CRUD)
  test_ai_summarizer.py            # 8 unit tests (relevance scoring, cost calc)
  test_document_processor.py       # 7 unit tests (dedup, content hash, process_entries)
  test_notifier.py                 # 12 unit tests (filters, payload, HMAC, delivery, idempotency)
  test_auth.py                     # 19 auth tests (register, login, logout, protected routes, API key)
  test_billing.py                  # 35 billing tests (tiers, channel gating, Stripe checkout/portal/webhooks, idempotency)
  test_security.py                 # 20 security tests (CSRF enforcement, CORS, SECRET_KEY, SameSite cookies)
  test_observability.py            # 41 observability tests (JSON logging, middleware, health metrics, scheduler metrics, error counter, health probes)
  test_password_reset.py           # 33 password reset tests (token generation/validation, routes, anti-enumeration, email, session clearing, edge cases)
  test_topics.py                   # 28 topic subscription tests (model property, query filtering, routes, dashboard filtering, edge cases)
  test_hardening.py                # 32 hardening tests (CFTC scraper strategies, CSV export, channel ownership, session caching)
  test_phase2.py                   # 20 tests (auth rate limiting, session user scoping, notification retry, filter consolidation, asyncio loop reuse)
  test_bugfixes.py                 # 36 tests (Stripe webhook, billing fresh user, email XSS, SSRF, float parse, API ownership, count total, retry deleted doc, scheduler commit, ai_summarizer empty response, batch dedup, auth validation, empty URL skip, HTML unescape, regen key guard)
  test_sprint8_notifications.py    # 44 tests (Slack channels, channel toggle, channel test button, notification history page + API, HTMX partials)
  test_beta_sprint.py              # 53 tests (beta mode config, founding member registration, new pricing tiers, free tier gating, onboarding flow, dashboard nudge)
alembic/
  env.py                           # Migration env, imports all models (incl. User, StripeEvent), overrides URL from config
  versions/001_initial_schema.py   # Initial: feed_sources, feed_documents, processed_alerts
  versions/002_notification_channels.py  # Notification: notification_channels, notification_logs
  versions/003_add_users.py        # Users table + notification_channels.user_id FK
  versions/004_add_stripe_billing.py  # Stripe columns on users + stripe_events table
  versions/005_add_subscribed_topics.py  # subscribed_topics column on users
  versions/006_add_notification_retry.py  # retry_count + next_retry_at on notification_logs
  versions/007_add_beta_columns.py        # enabled on notification_channels, is_founding_member + beta_enrolled_at on users
```

### Database Schema (7 tables)
1. **feed_sources** — RSS/HTML feed URLs, agency, type, enabled flag, last_checked_at
2. **feed_documents** — Individual regulatory documents, deduped by external_id, processing_status (pending/completed/failed)
3. **processed_alerts** — AI-generated summaries, key_points (JSON), topics (JSON-encoded list), relevance_score, cost tracking
4. **notification_channels** — Webhook/email/Slack delivery targets with filters (agency, min_relevance_score, topic_filter), user_id FK, enabled toggle
5. **notification_logs** — Delivery audit trail (sent/failed, error_message, retry_count, next_retry_at, idempotency)
6. **users** — User accounts (email, hashed_password, api_key, is_active, stripe_customer_id, stripe_subscription_id, subscription_tier, subscription_status, tier_updated_at, subscribed_topics, is_founding_member, beta_enrolled_at)
7. **stripe_events** — Webhook idempotency (event ID PK, event_type, processed_at)

### Data Flow
1. **Fetch**: CLI `fetch` command or APScheduler background job → FeedFetcher (RSS) or CFTC scraper (HTML) → FeedEntry objects
2. **Dedup**: document_processor deduplicates against DB → inserts new FeedDocument rows (status=pending)
3. **Summarize**: ai_summarizer calls Claude → parses JSON response → creates ProcessedAlert, marks doc completed
4. **Notify**: notifier checks enabled channels, applies filters, delivers via HTTP POST (webhooks) or SMTP (email), logs results
5. **Serve**: API serves FeedDocument + ProcessedAlert as combined UpdateResponse with filtering/pagination

### API Endpoints (v0.9.0-beta)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Full health check (backward compat, same as /ready) |
| GET | `/api/health/live` | No | Liveness probe — no DB, sub-1ms |
| GET | `/api/health/ready` | No | Readiness probe — full system check |
| GET | `/api/updates` | Yes* | List updates (filters: agency, topic, min_score, limit, offset) |
| GET | `/api/updates/export` | Yes* | Export updates as CSV download (same filters + limit up to 10000) |
| GET | `/api/updates/{id}` | Yes* | Single update by ID |
| GET | `/api/channels` | Yes* | List notification channels (user-scoped) |
| POST | `/api/channels` | Yes* | Create webhook, email, or Slack channel |
| PATCH | `/api/channels/{id}` | Yes* | Toggle channel enabled/disabled |
| DELETE | `/api/channels/{id}` | Yes* | Delete channel and its logs (ownership enforced) |
| GET | `/api/notifications` | Yes* | List notification delivery logs (user-scoped, filters: channel_id, status) |

*Auth is optional — disabled when `API_KEYS` env var is empty. Accepts both env-based and user DB-based API keys. Channel endpoints are scoped to the authenticated user (list only own channels, can only delete own channels). Free tier restrictions: SEC-only alerts, email-only channels, no AI summaries.

### Auth Routes (Session-Based)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/login` | Public | Login form |
| POST | `/login` | Public (5/min) | Authenticate, set session cookie, redirect to `/` |
| GET | `/register` | Public | Registration form |
| POST | `/register` | Public (3/min) | Create user, auto-login, redirect to `/welcome` |
| POST | `/logout` | Session | Clear session, redirect to `/login` |
| GET | `/account` | Session | Profile + API key display |
| POST | `/account/regenerate-key` | Session | Regenerate user's API key |
| GET | `/forgot-password` | Public | Forgot password form |
| POST | `/forgot-password` | Public (3/min) | Send password reset email (anti-enumeration) |
| GET | `/reset-password?token=` | Public | Validate token, show new password form |
| POST | `/reset-password` | Public | Reset password, clear session |

### Billing Routes (Stripe)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/pricing` | Public | Pricing page with tier comparison |
| GET | `/billing` | Session | Billing dashboard (tier badge, usage, manage/upgrade) |
| POST | `/billing/checkout` | Session | Create Stripe Checkout Session → redirect |
| POST | `/billing/portal` | Session | Create Stripe Customer Portal → redirect |
| POST | `/webhooks/stripe` | Signature | Stripe webhook (signature-verified, idempotent) |

### Subscription Tiers
| | Free | Pro ($79/mo) | Team ($199/mo) | Enterprise (custom) |
|---|---|---|---|---|
| Channels | 1 max (email only) | Unlimited | Unlimited | Unlimited |
| Channel types | Email | Email, Webhook, Slack | Email, Webhook, Slack | Email, Webhook, Slack |
| Agencies | SEC only | SEC + CFTC | SEC + CFTC | SEC + CFTC |
| AI summaries | Hidden | Full access | Full access | Full access |
| API rate | 10/min | 100/min | 100/min | 100/min |

**Beta mode**: When `BETA_MODE=True` (default), new signups receive Pro tier free and are flagged as founding members. Founding members get 40% off at GA pricing.

### Stripe Webhook Events Handled
- `checkout.session.completed` — Upgrades user to Pro tier
- `customer.subscription.updated` — Syncs tier/status from Stripe
- `customer.subscription.deleted` — Downgrades to Free, disables excess channels, restricts to email-only
- `invoice.payment_failed` — Sets status to past_due (keeps Pro tier)

Webhook idempotency: `stripe_events` table tracks processed event IDs. Duplicate events are skipped. Subscription ID matching prevents stale/out-of-order events from corrupting tier state.

### Authentication
- **Dashboard**: Session cookies via Starlette `SessionMiddleware` (signed with `SECRET_KEY`)
- **API**: `X-API-Key` header — checks env-based `API_KEYS` first, then DB user `api_key`
- Empty `API_KEYS` = API auth disabled (dev mode)
- Health and about endpoints are always public
- Protected dashboard routes redirect to `/login` when not authenticated
- Channels are scoped per-user (each user only sees/manages their own)

### Security
- **CSRF Protection**: Session-stored token (`secrets.token_urlsafe(32)`) validated via `validate_csrf` FastAPI dependency. Dual validation: `X-CSRFToken` header (HTMX) or `csrftoken` form field (standard forms). Timing-safe comparison via `secrets.compare_digest()`. Token rotation on login (prevents session fixation).
- **CORS**: Restricted to `BASE_URL` origin (default `http://localhost:8000`). Explicit `allow_headers` whitelist: `Content-Type`, `X-CSRFToken`, `X-API-Key`, `X-Requested-With`. Credentials allowed. 10-minute preflight cache.
- **Session Cookies**: `SameSite=Lax` (prevents cross-site cookie sending), `max_age=14 days`, `https_only` gated on production (Postgres = HTTPS, SQLite = dev HTTP).
- **SECRET_KEY**: Default value logs startup warning with generation command. Not fatal for dev.
- **CSRF-exempt routes**: `POST /webhooks/stripe` (Stripe signature verification), `POST /api/channels` + `DELETE /api/channels/{id}` (API key auth, not session cookies).
- **CSRF in templates**: `get_csrf_token(request)` registered as Jinja2 global function. HTMX requests inherit `X-CSRFToken` header via `hx-headers` on `<body>` tag. Standard forms use `<input type="hidden" name="csrftoken">`.
- **Tests**: Business tests bypass CSRF via `app.dependency_overrides[validate_csrf] = noop_csrf`. Security tests (`test_security.py`, 20 tests) verify real CSRF enforcement.
- **SSRF Prevention**: Webhook URLs validated before channel creation — blocks private/reserved IPs (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x), loopback hostnames (localhost, *.local), non-HTTP schemes, and DNS rebinding to internal IPs. Enforced in both API and dashboard channel creation. (`validation.py`)
- **Email XSS Prevention**: All user-controlled fields (doc title, agency, summary, URL, topics) HTML-escaped via `html.escape()` before injection into email body HTML. Prevents script injection via malicious document data.
- **Stripe Webhook Safety**: Handler failures return HTTP 500 (not 200) so Stripe retries. Events are NOT recorded on failure (prevents permanently losing critical events like checkout.session.completed).
- **API Channel Ownership**: Both API key and session-authenticated users can only delete their own channels. Cross-user delete returns 404 (prevents channel ID enumeration).

### Observability
- **Structured logging**: `JSONFormatter` produces one JSON object per log line (timestamp, level, logger, message, module, request_id). Configured via `configure_logging()` called in lifespan.
- **Log format**: `LOG_FORMAT` config setting — `"json"` (production default) or `"text"` (dev). Applied via `logging.config.dictConfig()` with `disable_existing_loggers: False`.
- **Request tracking**: Pure ASGI `RequestLoggingMiddleware` generates 12-char hex `request_id` per request, sets `request_id_var` ContextVar, injects `x-request-id` response header, logs method/path/status/duration.
- **Scheduler metrics**: Thread-safe `SchedulerMetrics` dataclass tracks cycle counts (total/success/partial/error), last_run_at, duration, status. Integrated into `_run_fetch_cycle()`.
- **Error counting**: Thread-safe `ErrorCounter` with total + per-module breakdown. Records errors from scheduler and middleware.
- **Enhanced health endpoint**: `/api/health` returns original 5 fields plus `uptime_seconds`, `database_connected`, `scheduler` (status, cycle counts, timing), `errors` (total, by_module). Status is `"degraded"` when DB unreachable or scheduler in error state.
- **Security**: `last_error` truncated to type+message (max 200 chars), never full traceback. Not exposed in health endpoint (stays in logs only).
- **Zero dependencies**: All observability via stdlib `logging`, `json`, `contextvars`, `threading`.

### Notification System
- **Webhook channels**: HTTP POST with JSON payload, optional HMAC-SHA256 signing (`X-Signature-256` header)
- **Slack channels**: Incoming webhook integration (URL must start with `https://hooks.slack.com/`), formatted Slack blocks
- **Email channels**: HTML email via SMTP with TLS support
- **Channel toggle**: Channels can be enabled/disabled via PATCH endpoint or dashboard UI toggle
- **Channel test**: Dashboard "Test" button sends a test notification to verify channel configuration
- **Filters**: min_relevance_score, agency_filter, topic_filter (all optional per channel)
- **Idempotency**: NotificationLog prevents duplicate delivery
- **Retry**: Failed notifications are retried with exponential backoff (5min, 30min, 2hr). Max 3 retries. `retry_failed_notifications()` runs every scheduler cycle. Disabled channels stop retrying.
- **Notification history**: `/notifications` dashboard page + `/api/notifications` API endpoint with channel/status filtering and pagination
- **CLI**: `add-webhook`, `add-email`, `list-channels` commands

### Background Scheduler
- APScheduler `BackgroundScheduler` with configurable interval (`FETCH_INTERVAL_MINUTES`, default 30)
- Runs full pipeline: fetch → dedup → summarize → notify → retry failed notifications
- Starts/stops with FastAPI lifespan
- Single `asyncio.new_event_loop()` per cycle (reused across all sources, properly closed via `try/finally`)
- Metrics: cycle counts, duration, status tracked in `SchedulerMetrics` (thread-safe), exposed via `/api/health`

### Rate Limiting
- **slowapi** (wraps `limits` library) with in-memory storage
- **Per-user rate limiting**: Free=10/min, Pro/Enterprise=100/min (configurable via `FREE_RATE_LIMIT`, `PRO_RATE_LIMIT`)
- Key function returns `user:{id}` (session), `key:{api_key}` (API), or IP (unauthenticated)
- Rate limit value set via `contextvars.ContextVar` — key function sets it, limit callable reads it
- Applied to all `/api/*` endpoints except `/api/health`
- Auth endpoints rate limited: POST `/login` (5/min), POST `/register` (3/min), POST `/forgot-password` (3/min) — IP-based
- Rate limiter extracted to `rate_limit.py` (shared between api.py and auth.py to avoid circular imports)
- Dashboard routes (`/`, `/alerts`, `/channels`, `/about`) are NOT rate limited
- Stripe webhook rate limited to 30/min by IP
- Returns 429 with `Retry-After` header when exceeded

### Dashboard (Frontend)
- **HTMX + Tailwind CSS** served from the same FastAPI app via Jinja2 templates
- 12 HTML routes: `/`, `/alerts`, `/alerts/{id}`, `/channels` (GET/POST/PATCH/DELETE), `/topics` (GET/POST), `/notifications`, `/welcome`, `/about`
- Billing routes: `/pricing` (public), `/billing` (session)
- Auth routes: `/login`, `/register`, `/account`, `/forgot-password`, `/reset-password` (standalone pages, no sidebar)
- Templates in `src/regulatory_alerts/templates/` (base.html + pages/ + partials/)
- Static files in `src/regulatory_alerts/static/` (css/custom.css, js/app.js)
- HTMX live filtering on alerts list, OOB flash messages for channel CRUD
- Dashboard routes require session login; `/about` is public (landing page)
- Sidebar shows user email + logout button when logged in, Topics + Notifications nav links
- Responsive sidebar layout with mobile hamburger menu
- Dashboard home filters alerts by user's topic subscriptions (NULL = show all)
- Dashboard home shows "Set up first channel" nudge when user has zero channels
- `/welcome` onboarding page after registration with 3-step checklist (account, channel, topics)
- `/notifications` notification history page with channel/status filters, HTMX pagination

### CI/CD
- GitHub Actions workflow at `.github/workflows/ci.yml`
- **test** job: runs on Python 3.11 + 3.12, `ubuntu-latest`, in-memory SQLite
- **docker** job: builds Docker image on `main` pushes only (after tests pass)

### Feed Sources (8 total)
- **SEC (6 RSS feeds)**: Press Releases, Litigation Releases, Admin Proceedings, Proposed Rules, Final Rules, Speeches
- **CFTC (2 HTML scraped)**: Press Releases, Speeches & Testimony

## What Works (Built)
- [x] Complete SQLAlchemy 2.0 data model with relationships (5 tables)
- [x] Alembic migrations (001_initial_schema, 002_notification_channels, 003_add_users)
- [x] Feed fetching with rate limiting (SEC 8 req/sec) and retries
- [x] CFTC HTML scraper with regex pattern matching
- [x] Document deduplication (external_id + content_hash)
- [x] AI summarization with structured JSON output
- [x] Relevance scoring (rule-based: doc type + topics + title keywords)
- [x] API cost tracking per summarization
- [x] FastAPI REST API with 6 endpoints + CORS
- [x] API key authentication (optional, header-based)
- [x] Notification system (webhook + email) with filters and idempotency
- [x] Background scheduler (APScheduler, configurable interval)
- [x] CLI with 7 commands (init-db, list-feeds, fetch, serve, add-webhook, add-email, list-channels)
- [x] Config via .env with sensible defaults (moved into package, root shim for compat)
- [x] SQLite/PostgreSQL dual support
- [x] Docker packaging (Dockerfile + docker-compose with PostgreSQL)
- [x] Test suite — 484 tests passing (API, dashboard, auth, billing, security, observability, notifier, AI summarizer, document processor, password reset, topics, hardening, phase2, bugfixes, sprint8 notifications, beta sprint, prometheus, alerting, admin)
- [x] Technical debt resolved (no more sys.path hacks in src/, no circular imports, modern lifespan)
- [x] Frontend dashboard — HTMX + Tailwind CSS (7 routes, 19 tests)
- [x] Per-user rate limiting — slowapi with contextvars, Free=10/min, Pro=100/min
- [x] CI/CD — GitHub Actions (test on Python 3.11+3.12, Docker build on main)
- [x] User management — session-based auth, registration, login, per-user channels, DB-based API keys
- [x] Stripe billing — 4 tiers (Free/Pro/Team/Enterprise), Checkout Sessions, Customer Portal, webhook handling with idempotency, channel gating, per-user rate limits (35 tests)
- [x] Security hardening — CSRF protection (session tokens, dual validation), CORS lockdown, SameSite cookies, SECRET_KEY warning (20 tests)
- [x] Monitoring/observability — Structured JSON logging, request ID tracking, request logging middleware, scheduler metrics, error counting, enhanced health endpoint (41 tests)
- [x] Liveness/readiness probes — `/api/health/live` (no DB), `/api/health/ready` (full check), backward-compat `/api/health` (7 tests)
- [x] Password reset — Stateless signed tokens (itsdangerous), anti-enumeration, single-use via hash prefix, session clearing, email delivery (33 tests)
- [x] Topic subscriptions — Per-user topic preferences, dashboard filtering, topic management page, JSON column on User model (28 tests)
- [x] CFTC scraper hardened — 3 parsing strategies with automatic fallback (Drupal table → generic table → link context), retry on transient errors, multi-format date parsing (16 tests)
- [x] CSV export — `/api/updates/export` endpoint with all standard filters, BOM-encoded for Excel compat, Export button on alerts page (8 tests)
- [x] API channel ownership — list/delete endpoints scoped to authenticated user, prevents cross-user access (3 tests)
- [x] Session factory caching — `lru_cache` on engine/session factory prevents connection pool explosion (3 tests)
- [x] Alembic env fixed — imports all 7 models (was missing User + StripeEvent), migration 005 for subscribed_topics column
- [x] Graceful scheduler shutdown — `wait=True` ensures running jobs complete before exit
- [x] Auth rate limiting — POST /login (5/min), POST /register (3/min), POST /forgot-password (3/min) via shared rate_limit.py
- [x] Notification retry — Failed notifications retried with exponential backoff (5m→30m→2h), max 3 retries, integrated into scheduler cycle (20 tests)
- [x] Consolidated filter logic — `query_updates()` is the single source of truth for API list/export + dashboard
- [x] Asyncio event loop reuse — Single loop per scheduler cycle (not per-source), properly closed
- [x] list_channels session user scoping — Filters by session user_id when no API key user present
- [x] Dashboard channel delete 404 — Returns 404 (not 403) for cross-user delete attempts (prevents enumeration)
- [x] **Security Audit + Bug Fix Sprint (20 bugs fixed, 36 tests)**:
  - Stripe webhook no longer swallows handler errors — returns 500 for Stripe retry
  - Billing page re-fetches user from DB to get fresh subscription tier
  - Email body HTML-escapes all user-controlled fields (XSS prevention)
  - Webhook URL validation blocks SSRF (private IPs, DNS rebinding, non-HTTP schemes)
  - Dashboard float parse error shows validation message (not 500 crash)
  - API delete_channel checks ownership for session users (not just API key users)
  - API /updates count returns total matching results (not page size)
  - Notification retry gracefully handles deleted FeedDocuments
  - Scheduler uses single commit per source (docs + notifications in same transaction)
  - Input validation module (`validation.py`) for reusable security checks
  - AI summarizer handles empty response.content without IndexError
  - Document processor deduplicates within same batch (prevents IntegrityError)
  - Auth: password max-length (128), basic email format validation
  - Auth: regenerate_api_key guards against deleted user
  - Billing: invalid client_reference_id handled gracefully (not crash)
  - Billing: checkout_session.url null guard
  - Feed fetcher: retries on ConnectError (DNS failures), skips empty URLs
  - CFTC scraper: retries on HTTPStatusError (503 etc.), HTML-unescapes scraped titles
  - Notifier: SMTP socket timeout re-set after TLS upgrade
- [x] **Sprint 8 — Slack channels, toggle, test, notification history (44 tests)**:
  - Slack notification channel type (incoming webhooks with formatted blocks)
  - Channel enable/disable toggle (PATCH `/api/channels/{id}`, dashboard UI switch)
  - Channel test button (sends test notification to verify configuration)
  - Notification history page (`/notifications`) with channel/status filters and HTMX pagination
  - Notification history API (`GET /api/notifications`) with user-scoped delivery logs
  - Alembic migration 007 adds `enabled` column on notification_channels + beta columns on users
- [x] **Sprint 9 — Founding Member Beta v0.9.0-beta (53 tests)**:
  - Beta mode (`BETA_MODE=True`): new signups get Pro tier free, flagged as founding members
  - New 4-tier pricing: Free ($0), Pro ($79/mo), Team ($199/mo), Enterprise (custom)
  - Free tier feature gating: email-only channels, SEC-only alerts, AI summaries hidden
  - Onboarding flow: `/welcome` page with 3-step checklist (account, channel, topics)
  - Dashboard "set up channel" nudge for new users with zero channels
  - Founding member badge + number on welcome/billing pages
  - Updated pricing page with beta banner, "FREE DURING BETA" badge, 4-tier grid
  - `is_founding_member` + `beta_enrolled_at` columns on User model
  - `FREE_MAX_CHANNELS=1` (was 2), configurable beta settings in config
- [x] **Sprint 10 — Prometheus Metrics, System Alerting, Admin Dashboard (55 tests)**:
  - Prometheus metrics via `/metrics` endpoint (no auth, Prometheus text format)
  - `PrometheusMetrics` class in observability.py: uptime, scheduler cycles, errors, DB counts, users by tier, HTTP requests
  - Delta-inc pattern bridges absolute singleton values to Prometheus monotonic counters
  - HTTP request counter in `RequestLoggingMiddleware` (try/except to never break requests)
  - System alerting module (`alerting.py`): email admin on scheduler failures (status=error OR failed_cycles>=2)
  - Thread-safe cooldown enforcement (configurable `ALERT_COOLDOWN_MINUTES`, default 60)
  - Alerting hook in scheduler (lazy import, wrapped in try/except after both success and failure)
  - Admin dashboard (`/admin`): stats overview, user management, system health
  - User management: toggle active, set tier, toggle admin (self-deactivation/demotion blocked)
  - Admin access control: `is_admin` column on User model, 403 for non-admins
  - Admin sidebar link (conditional, gear icon, only visible to admins)
  - Alembic migration 008 adds `is_admin` column
  - Config: `ALERTING_ENABLED`, `ALERT_EMAIL`, `ALERT_COOLDOWN_MINUTES`
  - Dependency: `prometheus-client>=0.21.0`

## What Needs Work / Known Issues
- [ ] **Email delivery untested with real SMTP** — mocked in tests but needs real SMTP testing
- [x] ~~**CFTC scraper is regex-based**~~ — Now has 3 cascading parsing strategies with automatic fallback
- [x] ~~**No topic subscriptions**~~ — Per-user topic subscriptions with dashboard filtering
- [x] ~~**No password reset**~~ — Full forgot-password/reset flow with signed tokens
- [x] ~~**No CSRF tokens**~~ — CSRF protection implemented with session tokens + dual validation
- [x] ~~**CORS unrestricted**~~ — CORS restricted to `BASE_URL` with explicit header whitelist

## Current Status
**Phase: Founding Member Beta (v0.10.0-beta) — Full feature set + ops tooling complete**

The full data pipeline (fetch → dedup → summarize → notify → retry → serve) is functional with background scheduling, push notifications with retry (webhook, email, Slack), session-based user auth, per-user channels, Stripe billing with 4 tiers (Free/Pro/Team/Enterprise), per-user rate limiting, auth rate limiting, security hardening (CSRF, CORS, SameSite cookies, SSRF prevention, XSS prevention), monitoring/observability (structured logging, health metrics, error tracking, Prometheus metrics), system alerting (email on scheduler failures), admin dashboard (user management, system health), password reset flow, per-user topic subscriptions, CSV export, hardened CFTC scraper, Docker deployment, CI/CD, a frontend dashboard, beta mode with founding member tracking, and 484 tests. The system can:
1. Initialize the DB and seed 8 feed sources
2. Automatically fetch SEC RSS feeds and scrape CFTC HTML pages on a schedule (with retry + fallback)
3. Deduplicate documents against the database
4. Generate AI summaries via Claude Haiku 4.5
5. Deliver notifications to webhook, email, and Slack channels with filtering
6. Serve results via authenticated REST API with filtering, pagination, and per-user rate limiting
7. Display a web dashboard for browsing alerts, managing channels, and viewing notification history
8. Register users with onboarding flow, login/logout with session cookies, per-user notification channels
9. Accept Stripe payments (Pro $79/mo, Team $199/mo), manage subscriptions via Customer Portal
10. Enforce tier limits (channel count/type, agency access, AI summaries, API rate) with automatic downgrade on cancellation
11. Deploy via Docker Compose with PostgreSQL
12. Run CI tests and Docker builds automatically via GitHub Actions
13. Reset forgotten passwords via secure email tokens (anti-enumeration, single-use)
14. Subscribe to specific regulatory topics, dashboard auto-filters by preferences
15. Export regulatory alerts as CSV for compliance audit trails
16. Automatically retry failed webhook/email/Slack notifications with exponential backoff
17. Rate limit authentication endpoints to prevent brute-force attacks
18. Onboard new users with founding member badges and 3-step setup checklist
19. Toggle notification channels on/off and send test notifications to verify configuration

## Next Steps (Priority Order)
1. **Alerting** — Error alerting via notification channels (email/webhook) when health degrades
2. **Prometheus metrics** — Add `/metrics` endpoint for observability stack integration
3. **Admin dashboard** — Admin-only view of all users, system metrics, manual feed trigger

## Docker Quick Start
```bash
# 1. Copy .env.example to .env and set ANTHROPIC_API_KEY
cp .env.example .env

# 2. Start PostgreSQL + API
docker compose up -d

# 3. API available at http://localhost:8000
# Auto-runs: alembic upgrade head → seed feeds → start uvicorn + scheduler
```

## Gotchas & Edge Cases (for the next developer)
- **Config location**: The real config is `src/regulatory_alerts/config.py`. Root `config.py` is a shim that adds `src/` to sys.path and re-exports. Alembic and `scripts/init_feeds.py` import from the root shim.
- **`_PROJECT_ROOT` in config**: Uses `Path(__file__).resolve().parents[2]` (3 levels up from `src/regulatory_alerts/config.py`) to find `.env`. If you move config.py, this breaks.
- **Circular imports**: Removed the old bottom-of-file hacks. SQLAlchemy resolves string-based relationship references when all models are imported in `models/__init__.py`. Don't add direct cross-imports between model files.
- **Pydantic Settings is frozen**: You can't `patch.object` on computed properties (like `api_keys_list`). In tests, set the underlying string field directly: `settings.API_KEYS = "key1,key2"`.
- **SQLite + threads**: In-memory SQLite doesn't work across threads (TestClient uses threads). Tests use `StaticPool` + `check_same_thread=False`. See `tests/conftest.py`.
- **Scheduler imports are lazy**: `start_scheduler`/`stop_scheduler` are imported inside the lifespan function, not at module level. When mocking in tests, patch at `regulatory_alerts.core.scheduler.start_scheduler`, not on the api module.
- **PostgreSQL drivers**: `requirements.txt` has `asyncpg` and `psycopg2-binary` uncommented (needed for Docker). Local SQLite dev doesn't use them but they install harmlessly.
- **CFTC scraper resilience**: Uses 3 cascading parsing strategies (Drupal table → generic table → link context) with automatic fallback. If all 3 fail, logs a WARNING. Check `cftc_scraper.py` if CFTC feeds go quiet. The `parse_cftc_html()` function can be tested independently with saved HTML snapshots.
- **Alembic URL override**: `alembic/env.py` overrides the URL from `alembic.ini` with `config.py`'s `DATABASE_URL_SYNC`. The ini file value is never actually used.
- **bcrypt directly, no passlib**: We use `bcrypt` library directly (not `passlib`) because `passlib` has a known incompatibility with `bcrypt>=4.0` (wrap bug detection failure). Import as `import bcrypt as _bcrypt`.
- **Auth tests need 6 session mocks**: Tests must mock `api`, `rate_limit`, `dashboard`, `auth`, `billing` `.get_sync_session_factory`. Missing any one causes tests to use the real DB. The `rate_limit` mock was added when limiter was extracted to shared module.
- **Test login via registration**: Dashboard test client fixture calls `POST /register` to create a user and auto-set session cookie. The `TestClient` preserves cookies between requests.
- **SessionMiddleware requires itsdangerous**: Added to requirements.txt. Without it, Starlette's SessionMiddleware fails to import.
- **Per-user rate limiting uses contextvars**: `_rate_limit_key(request)` sets a ContextVar, `_dynamic_rate_limit()` (no args) reads it. slowapi's limit callable takes NO arguments — this is the workaround.
- **Billing tests need 5 session factory mocks**: api, dashboard, auth, billing, plus scheduler start/stop. Missing billing mock causes tests to use the real DB.
- **Stripe webhook must use raw body**: `await request.body()` before any JSON parsing. Signature verification fails if the body is consumed/modified.
- **Channel gating is enforced in BOTH paths**: `api.py` `create_channel()` and `dashboard.py` `channels_create()` both call `check_channel_limit()` from billing.py.
- **Downgrade disables excess channels**: When tier drops to free, excess channels get `enabled=False` (not deleted). User can re-enable after upgrading or deleting extras.
- **CSRF uses Jinja2 globals, not middleware**: `BaseHTTPMiddleware` wraps requests in `_CachedRequest` which doesn't propagate session scope. CSRF token is exposed via `get_csrf_token` registered on Jinja2 env globals (called in `_install_csrf_globals()` at module load). Templates use `{{ get_csrf_token(request) }}`.
- **CSRF test bypass pattern**: Business logic tests add `app.dependency_overrides[validate_csrf] = noop_csrf` (async function from conftest). Security tests (`test_security.py`) use a `csrf_client` fixture WITHOUT the override to test real enforcement.
- **CSRF for HTMX vs standard forms**: HTMX requests send `X-CSRFToken` via `hx-headers` on body tag (inherited by all HTMX requests). Standard HTML forms use a hidden `csrftoken` input. `validate_csrf` checks header first, then form field.
- **Observability singletons need reset in tests**: `scheduler_metrics.reset()`, `error_counter.reset()`, `reset_uptime()` — use autouse fixture. Without reset, state leaks between tests.
- **Mock `configure_logging` in test client fixtures**: `configure_logging()` replaces root logger handlers with JSON stdout handler, which bypasses pytest caplog. Mock it to keep caplog working.
- **RequestLoggingMiddleware is pure ASGI**: NOT `BaseHTTPMiddleware` (which breaks session access). Uses `send_wrapper` closure to capture status code and inject `x-request-id` header.
- **Rate limiter reset in tests**: `limiter.reset()` in autouse conftest fixture. Without this, rate limit counters accumulate across tests and cause 429 responses in later tests.
- **Rate limiter extracted to `rate_limit.py`**: Shared between `api.py` and `auth.py` to avoid circular imports (api.py imports auth.py's router). Both import `limiter` and `_dynamic_rate_limit` from `rate_limit.py`.
- **Notification retry backoff**: [5min, 30min, 2hr]. After `MAX_RETRIES` (3), `next_retry_at` is set to None (no more retries). Disabled channels have their retry logs permanently failed.
- **API filter logic consolidated**: `list_updates` and `export_updates` in api.py now call `query_updates()` from dashboard.py (lazy import to avoid circular deps). Eliminates duplicate filter code.
- **Scheduler event loop**: Uses `asyncio.new_event_loop()` + `try/finally: loop.close()` per cycle. All sources run in the same loop via `loop.run_until_complete()`.
- **Slack channel URL validation**: Must start with `https://hooks.slack.com/`. Enforced in both API and dashboard channel creation.
- **Channel toggle (PATCH)**: Uses same ownership check pattern as DELETE — returns 404 for cross-user attempts. Only toggles `enabled` field.
- **Beta mode in tests**: Autouse fixture `_disable_beta_mode` in conftest sets `BETA_MODE=False` so existing tests aren't affected. Sprint 9 tests explicitly enable beta mode when needed.
- **Free tier gating is multi-layered**: Channel type (email only) enforced at creation. Agency (SEC only) enforced at query time via `restrict_agency` param. AI summaries hidden via `hide_ai` flag in `_build_update()`. All three must be consistent.
- **Founding member number**: Calculated by counting users with `is_founding_member=True` AND `id <= current_user.id`. This gives a stable, monotonically increasing number per user.
- **Onboarding state is session-based**: `request.session["onboarding_complete"]` is set when all 3 steps are done. Not persisted in DB — resets on session expiry (acceptable for welcome page).
- **Registration redirect changed**: POST `/register` redirects to `/welcome` (not `/`). Tests that check registration redirect must assert `/welcome`.

## Local Development
```bash
# Install deps
pip install -r requirements.txt
pip install -e .

# Init database + seed feeds (SQLite default)
python -m regulatory_alerts.cli init-db

# Fetch + summarize
python -m regulatory_alerts.cli fetch

# Start API server
python -m regulatory_alerts.cli serve

# Run tests
pytest
```
