# Security Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add structured, attack-focused logging across the NestJS security library with a default Nest logger adapter and override support for application-specific loggers.

**Architecture:** Introduce a `SecurityLoggerPort` plus a `SecurityLoggingService` in the application layer, then bind the port to a default Nest adapter or a noop/custom override in `SecurityModule`. Integrate logging into guards, middleware, abuse detection, and audit flow so attack events always expose IP and key triage fields without leaking sensitive data.

**Tech Stack:** NestJS, TypeScript, Jest, RxJS, existing Redis-backed security library

---

### Task 1: Add logging contracts and default adapters

**Files:**
- Create: `libs/security/src/application/ports/security-logger.port.ts`
- Create: `libs/security/src/types/security-log-entry.types.ts`
- Create: `libs/security/src/outbound/logging/nest-security-logger.adapter.ts`
- Create: `libs/security/src/outbound/logging/noop-security-logger.adapter.ts`
- Test: `libs/security/src/outbound/logging/nest-security-logger.adapter.spec.ts`

- [ ] **Step 1: Write the failing adapter test**
- [ ] **Step 2: Run test to verify it fails**
  - Run: `npm test -- nest-security-logger.adapter.spec.ts`
- [ ] **Step 3: Implement `SecurityLoggerPort`, `SecurityLogEntry`, and adapters**
- [ ] **Step 4: Run test to verify it passes**
  - Run: `npm test -- nest-security-logger.adapter.spec.ts`

### Task 2: Add `SecurityLoggingService` with filtering, redaction, and payload shaping

**Files:**
- Create: `libs/security/src/application/services/security-logging.service.ts`
- Test: `libs/security/src/application/services/security-logging.service.spec.ts`
- Modify: `libs/security/src/config/security-module-options.interface.ts`

- [ ] **Step 1: Write failing tests for min-level filtering, redaction, `includeHeaders`, `includeQueryMetadata`, and message shaping that always includes `ip`, `method`, and `path` for attack events**
- [ ] **Step 2: Run test to verify it fails**
  - Run: `npm test -- security-logging.service.spec.ts`
- [ ] **Step 3: Implement `SecurityLoggingService` and expand logging config types/defaults**
- [ ] **Step 4: Run test to verify it passes**
  - Run: `npm test -- security-logging.service.spec.ts`

### Task 3: Wire logger providers into `SecurityModule`

**Files:**
- Modify: `libs/security/src/module/security.module.ts`
- Modify: `libs/security/src/module/security.module.spec.ts`
- Modify: `libs/security/src/constants/security.constants.ts`
- Modify: `libs/security/src/index.ts`

- [ ] **Step 1: Write failing module test for logger provider precedence and required exports (`SECURITY_LOGGER`, `SecurityLoggingService`, `PolicyRegistryService`)**
- [ ] **Step 2: Run test to verify it fails**
  - Run: `npm test -- security.module.spec.ts`
- [ ] **Step 3: Add `SECURITY_LOGGER` token and provider graph in module, exporting `SECURITY_LOGGER` and `SecurityLoggingService`**
- [ ] **Step 4: Run test to verify it passes**
  - Run: `npm test -- security.module.spec.ts`

### Task 4: Integrate logging into request hardening and enforcement flow

**Files:**
- Modify: `libs/security/src/inbound/middleware/request-fingerprint.middleware.ts`
- Modify: `libs/security/src/inbound/middleware/body-limit.middleware.ts`
- Modify: `libs/security/src/inbound/middleware/header-sanity.middleware.ts`
- Modify: `libs/security/src/inbound/guards/rate-limit.guard.ts`
- Modify: `libs/security/src/inbound/guards/blocklist.guard.ts`
- Test: `libs/security/src/inbound/middleware/body-limit.middleware.spec.ts`
- Test: `libs/security/src/inbound/middleware/header-sanity.middleware.spec.ts`
- Test: `libs/security/src/inbound/middleware/request-fingerprint.middleware.spec.ts`
- Test: `libs/security/src/inbound/guards/rate-limit.guard.spec.ts`
- Test: `libs/security/src/inbound/guards/blocklist.guard.spec.ts`

- [ ] **Step 1: Add failing assertions for `fingerprint.resolved` (verbose only), `fingerprint.proxy-header-missing` (`trustProxy=true`), `request_rejected.body_too_large`, `request_rejected.invalid_header`, `rate_limit.exceeded`, and `blocklist.rejected`, including human-readable `ip/method/path` and enriched metadata (`proxyChain`, `blockExpiresAt`) where applicable**
- [ ] **Step 2: Run targeted tests to verify they fail**
  - Run: `npm test -- request-fingerprint.middleware.spec.ts body-limit.middleware.spec.ts header-sanity.middleware.spec.ts rate-limit.guard.spec.ts blocklist.guard.spec.ts`
- [ ] **Step 3: Inject `SecurityLoggingService` and emit structured attack logs**
- [ ] **Step 4: Run targeted tests to verify they pass**
  - Run: `npm test -- request-fingerprint.middleware.spec.ts body-limit.middleware.spec.ts header-sanity.middleware.spec.ts rate-limit.guard.spec.ts blocklist.guard.spec.ts`

### Task 5: Integrate logging into abuse detection and audit pipeline

**Files:**
- Modify: `libs/security/src/application/services/abuse-detection.service.ts`
- Modify: `libs/security/src/application/services/audit-log.service.ts`
- Modify: `libs/security/src/inbound/interceptors/audit.interceptor.ts`
- Test: `libs/security/src/application/services/abuse-detection.service.spec.ts`
- Test: `libs/security/src/application/services/audit-log.service.spec.ts`
- Test: `libs/security/src/inbound/interceptors/audit.interceptor.spec.ts`

- [ ] **Step 1: Add failing tests for `abuse.suspicious_path`, `abuse.404_burst`, `abuse.401_403_burst`, `abuse.rule_triggered`, `abuse.escalated`, `audit.request_completed`, and `audit.request_failed`, including `matchedPattern` and other triage metadata where applicable**
- [ ] **Step 2: Run targeted tests to verify they fail**
  - Run: `npm test -- abuse-detection.service.spec.ts audit-log.service.spec.ts audit.interceptor.spec.ts`
- [ ] **Step 3: Implement logging enrichment, `AuditEvent -> SecurityLogEntry` mapping that preserves triage fields, and success/error audit emission**
- [ ] **Step 4: Run targeted tests to verify they pass**
  - Run: `npm test -- abuse-detection.service.spec.ts audit-log.service.spec.ts audit.interceptor.spec.ts`

### Task 6: Verify `logging.enabled` and `persistAudit` semantics

**Files:**
- Modify: `libs/security/src/application/services/audit-log.service.ts`
- Modify: `libs/security/src/application/services/audit-log.service.spec.ts`
- Modify: `libs/security/src/application/services/security-logging.service.spec.ts`

- [ ] **Step 1: Add failing tests for the `enabled/persistAudit` truth table and no-double-log behavior**
- [ ] **Step 2: Run targeted tests to verify they fail**
  - Run: `npm test -- audit-log.service.spec.ts security-logging.service.spec.ts`
- [ ] **Step 3: Implement the truth table behavior and keep persistence/logging decoupled**
- [ ] **Step 4: Run targeted tests to verify they pass**
  - Run: `npm test -- audit-log.service.spec.ts security-logging.service.spec.ts`

### Task 7: Update docs and verify the whole library

**Files:**
- Modify: `README.md`
- Modify: `task.md`

- [ ] **Step 1: Document logging config, adapter override, and attack log examples**
- [ ] **Step 2: Run full verification**
  - Run: `npm test && npm run typecheck && npm run build`
- [ ] **Step 3: Mark plan-related checklist items done and summarize remaining gaps, if any**
