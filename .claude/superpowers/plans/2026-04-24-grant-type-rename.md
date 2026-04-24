# Grant Type Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename OAuth grant values to RFC 6749 / RFC 6755 compliant forms: `authorization` → `authorization_code`, `did` → `urn:o3co:oauth:grant-type:did`. Align HOCON config keys and env vars accordingly.

**Architecture:** Hard break (no dual-accept). Wire values, HOCON config keys, policy input, and standalone template all change in one release. DID grant URN is fixed to `urn:o3co:oauth:grant-type:did` (owned by auth.provider as wire protocol definer). Audit event schema unchanged (`details.grant_type`), only values flow through automatically.

**Tech Stack:** TypeScript (Node.js), Vitest, Zod, Express, HOCON (`@o3co/hocon`).

**Spec:** `.claude/superpowers/specs/2026-04-24-grant-type-rename-design.md`

---

## File Structure

Files to modify (in execution order):

| File | Purpose | Change |
| --- | --- | --- |
| `packages/oauth/src/__tests__/oauthAuthorization.test.mts` | Module init registration test | Rename grant key assertions |
| `packages/oauth/src/oauthAuthorization.mts` | Grant registration + config lookup | Rename config key + registry key |
| `packages/oauth/src/__tests__/hooks.test.mts` | Policy/audit flow tests | Update policy grantType expectation |
| `packages/oauth/src/routes.mts` | Policy input hardcoded value | Update `grantType: "authorization"` |
| `packages/core/config/application.conf` | Core default HOCON | Rename `authorization` section + env var |
| `templates/standalone/config/application.conf` | Standalone default HOCON | Rename section + env vars |
| `packages/did/src/__tests__/did.test.mts` | DID grant unit tests | Update mock config key (internal only) |
| `packages/did/src/module.mts` | DID grant registration | Register fixed URN |
| `packages/did/src/__tests__/module.test.mts` | NEW — module init test for URN | Create |
| `templates/standalone/tests/index.test.js` | Standalone integration tests | Update `grant_type=authorization` wire values |
| `templates/standalone/tests/did-grant.test.js` | Standalone DID integration tests | Update all 8 `grant_type: "did"` to URN |
| `templates/standalone/src/__tests__/smoke.test.mts` | Standalone smoke tests | Update if any `authorization` references |
| `templates/standalone/README.md` / `.ja.md` | Standalone env var docs | Update table entries |
| `README.md` | Root README | Update ASCII diagram + env var |
| `packages/oauth/README.md` | OAuth package docs | Scan + update any remaining references |
| `packages/did/README.md` | DID package docs | Add URN fixed-value section + rationale |
| `CHANGELOG.md` | Root changelog | Add v0.5.0 Unreleased breaking entry |

**Constants introduced:**

- `DID_GRANT_TYPE = "urn:o3co:oauth:grant-type:did"` in `packages/did/src/module.mts` (module-scoped const)

---

## Task 1: Rename `authorization` grant registry key + config key

**Files:**

- Test: `packages/oauth/src/__tests__/oauthAuthorization.test.mts`
- Modify: `packages/oauth/src/oauthAuthorization.mts`

- [ ] **Step 1: Read the existing test file to understand current shape**

Run: `sed -n '140,170p;255,315p' packages/oauth/src/__tests__/oauthAuthorization.test.mts`
Note the lines that assert `ctx.grantRegistry.get("authorization")` and the test name strings referencing "authorization".

- [ ] **Step 2: Update test expectations to `authorization_code` (RED)**

In `packages/oauth/src/__tests__/oauthAuthorization.test.mts`, replace every occurrence of the string literal `"authorization"` that is used as a grant registry key with `"authorization_code"`. Do NOT change occurrences where the word is part of a longer identifier (e.g. `authorizationCode`, `Authorization`, or comments not about the grant).

Expected replacements (approximate):

- Line 146: `ctx.grantRegistry.get("authorization")` → `ctx.grantRegistry.get("authorization_code")`
- Line 169: `ctx.grantRegistry.get("authorization")` → `ctx.grantRegistry.get("authorization_code")`
- Line 260: `const handler = ctx.grantRegistry.get("authorization");` → `const handler = ctx.grantRegistry.get("authorization_code");`
- Line 294: `ctx.grantRegistry.get("authorization")` → `ctx.grantRegistry.get("authorization_code")`
- Line 311: `const handler = ctx.grantRegistry.get("authorization");` → `const handler = ctx.grantRegistry.get("authorization_code");`

Also update any inline mock config object in this test file that uses `authorization: {...}` as a config key to `authorization_code: {...}`.

- [ ] **Step 3: Run the tests to confirm they fail**

Run: `cd packages/oauth && pnpm exec vitest run src/__tests__/oauthAuthorization.test.mts`
Expected: several failures. Each failure should be either "registry.get returned undefined" or assertion about `authorization_code` mismatching registered `authorization`.

- [ ] **Step 4: Update implementation to register under new key**

Modify `packages/oauth/src/oauthAuthorization.mts`:

- Line 35: `if (grantsConfig.authorization?.enabled !== false) {` → `if (grantsConfig.authorization_code?.enabled !== false) {`
- Line 45: `context.grantRegistry.register("authorization", handler);` → `context.grantRegistry.register("authorization_code", handler);`

Keep all other lines (config / createAuthorizationGrant call / refresh_token branch) unchanged.

- [ ] **Step 5: Run the tests to confirm they pass**

Run: `cd packages/oauth && pnpm exec vitest run src/__tests__/oauthAuthorization.test.mts`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/oauth/src/oauthAuthorization.mts packages/oauth/src/__tests__/oauthAuthorization.test.mts
git commit -m "$(cat <<'EOF'
feat(oauth)!: rename authorization grant to authorization_code (RFC 6749)

- Registry key: "authorization" → "authorization_code"
- Config key: oauth.grants.authorization → oauth.grants.authorization_code
- Wire value: grant_type=authorization → grant_type=authorization_code

RFC 6749 §4.1.3 compliance. Hard break — legacy "authorization" value now
returns unsupported_grant_type.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Update policy input hardcoded value in routes

**Files:**

- Test: `packages/oauth/src/__tests__/hooks.test.mts`
- Modify: `packages/oauth/src/routes.mts`

- [ ] **Step 1: Inspect current policy input test**

Run: `sed -n '330,350p' packages/oauth/src/__tests__/hooks.test.mts`
Confirm line 339 is `expect(request.grantType).toBe("authorization");` (the spec item we need to rename).

- [ ] **Step 2: Update test expectation (RED)**

In `packages/oauth/src/__tests__/hooks.test.mts`, change line 339 from:

```typescript
expect(request.grantType).toBe("authorization");
```

to:

```typescript
expect(request.grantType).toBe("authorization_code");
```

- [ ] **Step 3: Run the tests to confirm failure**

Run: `cd packages/oauth && pnpm exec vitest run src/__tests__/hooks.test.mts`
Expected: the policy-input test fails, showing `received: "authorization"`.

- [ ] **Step 4: Update `routes.mts:466`**

Modify `packages/oauth/src/routes.mts` line 466 (inside the `grantPolicy.evaluate` call on the `/oauth/authorize` path):

```typescript
// Before
grantType: "authorization",
// After
grantType: "authorization_code",
```

- [ ] **Step 5: Run the tests to confirm pass**

Run: `cd packages/oauth && pnpm exec vitest run src/__tests__/hooks.test.mts`
Expected: all tests PASS.

- [ ] **Step 6: Run full oauth package tests to ensure no regression**

Run: `cd packages/oauth && pnpm test`
Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/oauth/src/routes.mts packages/oauth/src/__tests__/hooks.test.mts
git commit -m "$(cat <<'EOF'
feat(oauth)!: pass authorization_code to grantPolicy on /authorize

GrantPolicyRequest.grantType for the authorize phase was hardcoded to
"authorization" at routes.mts:466. Update to match the RFC 6749 wire
value "authorization_code".

Breaking for consumers implementing GrantPolicyHookBase and branching
on `case "authorization":` — rename to `case "authorization_code":`.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Rename HOCON config sections + env vars

**Files:**

- Modify: `packages/core/config/application.conf`
- Modify: `templates/standalone/config/application.conf`

- [ ] **Step 1: Update `packages/core/config/application.conf`**

Locate line 38:

```hocon
authorization { enabled = true, enabled = ${?OAUTH_GRANTS_AUTHORIZATION_ENABLED} }
```

Replace with:

```hocon
authorization_code { enabled = true, enabled = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED} }
```

- [ ] **Step 2: Update `templates/standalone/config/application.conf`**

Locate lines 38-45:

```hocon
authorization {
  enabled = true
  enabled = ${?OAUTH_GRANTS_AUTHORIZATION_ENABLED}
  pkce {
    requireS256 = false
    requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256}
  }
}
```

Replace with:

```hocon
authorization_code {
  enabled = true
  enabled = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED}
  pkce {
    requireS256 = false
    requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256}
  }
}
```

- [ ] **Step 3: Verify no other config files reference the old key**

Run: `grep -rn "grants\.authorization\b\|authorization {\s*enabled\|OAUTH_GRANTS_AUTHORIZATION_ENABLED\|OAUTH_GRANTS_AUTHORIZATION_PKCE" packages templates --include="*.conf" 2>/dev/null`
Expected output: empty (all occurrences updated).

- [ ] **Step 4: Run standalone smoke tests**

Run: `cd templates/standalone && pnpm test`
Expected: PASS (smoke test reads config and may exercise the rename).

If smoke test fails because the test itself references old config key, capture failures — they'll be fixed in Task 6.

- [ ] **Step 5: Commit**

```bash
git add packages/core/config/application.conf templates/standalone/config/application.conf
git commit -m "$(cat <<'EOF'
feat(config)!: rename oauth.grants.authorization to authorization_code

Align HOCON config section and env var names with RFC 6749 wire value.

- oauth.grants.authorization → oauth.grants.authorization_code
- OAUTH_GRANTS_AUTHORIZATION_ENABLED → OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED
- OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256 → OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256

Hard break. Consumers must update HOCON files and environment variables.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Rename DID grant to URN (registry key)

**Files:**

- Test: `packages/did/src/__tests__/did.test.mts`
- Create: `packages/did/src/__tests__/module.test.mts`
- Modify: `packages/did/src/module.mts`

- [ ] **Step 1: Update `did.test.mts` mock config**

The `did.test.mts` file uses a mock config with a sibling `authorization: { enabled: true }` key (not `authorization_code`). Since `createDidGrant` does not read this key (only `oauth.grants.did`), the test is not directly affected by our rename — but to keep the mock internally consistent with the rest of the codebase, update it.

In `packages/did/src/__tests__/did.test.mts`, find the `mockConfig` object (around line 33-46) and update the sibling key:

```typescript
// Before
grants: {
  session: { enabled: true },
  authorization: { enabled: true },
  refresh_token: { enabled: true },
  did: { enabled: true, algorithm: "ed25519_raw", messageMaxAgeSec: 300 },
},
// After
grants: {
  session: { enabled: true },
  authorization_code: { enabled: true },
  refresh_token: { enabled: true },
  did: { enabled: true, algorithm: "ed25519_raw", messageMaxAgeSec: 300 },
},
```

- [ ] **Step 2: Run DID unit tests to confirm they still pass**

Run: `cd packages/did && pnpm exec vitest run src/__tests__/did.test.mts`
Expected: PASS (the change is internal mock consistency, no behavior change).

- [ ] **Step 3: Create a new module-level test file (RED)**

Create `packages/did/src/__tests__/module.test.mts` with the following content:

```typescript
/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {
	GrantRegistry,
	createSymmetricKeyStore,
	type ModuleContext,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { oauthDidModule } from "../module.mjs";
import type { DidDocument, DidDocumentResolver } from "../resolver/types.mjs";

const DID_URN = "urn:o3co:oauth:grant-type:did";

const mockResolver: DidDocumentResolver = {
	async resolve(_did: string): Promise<DidDocument> {
		throw new Error("not expected to be called in this test");
	},
};

const buildContext = (
	didConfig: Record<string, unknown> | undefined,
): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: {
		oauth: {
			jwt: { secret: "test-secret" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: { did: didConfig },
		},
	} as unknown as ModuleContext["config"],
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	// Use ModuleContext["router"] to avoid coupling this package's tests
	// to the `express` type dependency (not declared in packages/did).
	router: {} as ModuleContext["router"],
});

describe("oauthDidModule", () => {
	it("registers DID grant under urn:o3co:oauth:grant-type:did when enabled", async () => {
		const ctx = buildContext({ enabled: true, supportedAlgorithms: ["ed25519_raw"] });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get(DID_URN)).toBeDefined();
	});

	it("does NOT register the bare 'did' string (URN-only policy)", async () => {
		const ctx = buildContext({ enabled: true, supportedAlgorithms: ["ed25519_raw"] });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get("did")).toBeUndefined();
	});

	it("is a no-op when did.enabled is false", async () => {
		const ctx = buildContext({ enabled: false });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get(DID_URN)).toBeUndefined();
		expect(ctx.grantRegistry.get("did")).toBeUndefined();
	});

	it("registers when did config is undefined (no explicit disable)", async () => {
		const ctx = buildContext(undefined);
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		// Current behavior: undefined config → enabled !== false, so registered.
		// Note: init() does not run the zod schema; it only checks `enabled === false`.
		expect(ctx.grantRegistry.get(DID_URN)).toBeDefined();
	});
});
```

- [ ] **Step 4: Run the new test to confirm failure**

Run: `cd packages/did && pnpm exec vitest run src/__tests__/module.test.mts`
Expected: failures. The current `module.mts` registers under `"did"`, so:

- "registers DID grant under urn:o3co:oauth:grant-type:did when enabled" → FAIL (returned undefined)
- "does NOT register the bare 'did' string" → FAIL (handler IS registered under "did")
- "is a no-op when did.enabled is false" → may already pass
- "registers when did config is missing" → FAIL

- [ ] **Step 5: Update `module.mts` to register under fixed URN**

Modify `packages/did/src/module.mts`:

```typescript
// At module top (after imports, before the oauthDidModule export)
const DID_GRANT_TYPE = "urn:o3co:oauth:grant-type:did" as const;
```

Change line 76 from:

```typescript
context.grantRegistry.register("did", handler);
```

to:

```typescript
context.grantRegistry.register(DID_GRANT_TYPE, handler);
```

- [ ] **Step 6: Run module.test.mts + did.test.mts to confirm pass**

Run: `cd packages/did && pnpm test`
Expected: all DID tests PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/did/src/module.mts packages/did/src/__tests__/module.test.mts packages/did/src/__tests__/did.test.mts
git commit -m "$(cat <<'EOF'
feat(did)!: register DID grant under urn:o3co:oauth:grant-type:did

Fixed URN owned by auth.provider (wire protocol definer). Bare "did"
grant_type is no longer registered and returns unsupported_grant_type.

Add module-level tests verifying URN registration, bare-string non-
registration, and enabled=false no-op.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update standalone integration tests (wire values)

**Files:**

- Modify: `templates/standalone/tests/index.test.js`
- Modify: `templates/standalone/tests/did-grant.test.js`
- Modify: `templates/standalone/src/__tests__/smoke.test.mts` (if needed)

- [ ] **Step 1: Inspect `index.test.js` for authorization wire values**

Run: `grep -n "grant_type=authorization\b\|grant_type: \"authorization\"" templates/standalone/tests/index.test.js`
Expected: finds lines around 161-176 using `grant_type=session` / `grant_type=authorization` / etc.

- [ ] **Step 2: Update wire values in `index.test.js`**

In `templates/standalone/tests/index.test.js`, replace `grant_type=authorization` with `grant_type=authorization_code` (URL-encoded form body).

Specifically the test "returns 400 for grant_type=authorization without a code" at line 175-176 becomes:

```javascript
it("returns 400 for grant_type=authorization_code without a code", async () => {
  const res = await client.post("/oauth/token", "grant_type=authorization_code", {
```

(The surrounding lines should stay intact — only rename the literal `authorization` within grant_type assertions and test names.)

- [ ] **Step 3: Update `did-grant.test.js` — all 8 occurrences**

In `templates/standalone/tests/did-grant.test.js`, replace every occurrence of `grant_type: "did"` with `grant_type: "urn:o3co:oauth:grant-type:did"` (8 locations per grep from Task 1 of this plan, lines 44, 95, 124, 133, 141, 150, 162, 185).

Also update the describe/it strings that mention "grant_type=did" (e.g. line 57) to reflect the URN.

- [ ] **Step 4: Inspect smoke test for authorization references**

Run: `grep -n "authorization\|\"did\"" templates/standalone/src/__tests__/smoke.test.mts`
Note any lines that assert specific grant_type registration or config.

- [ ] **Step 5: Update smoke test if it references old grant values**

If step 4 found literal `"authorization"` as grant key or config key, update to `"authorization_code"`.
If it references `"did"` as grant key, update to `"urn:o3co:oauth:grant-type:did"`.

(Wire-value test assertions like "`grant_type: 'unsupported'` returns 400" can remain as-is since they use fake values.)

- [ ] **Step 6: Run standalone tests**

Run: `cd templates/standalone && pnpm test`
Expected: PASS.

If tests fail because they depend on a running server instance (integration tests), accept failures that require external services (auth.provider server). Unit-style and smoke tests that don't require a live server should PASS.

- [ ] **Step 7: Commit**

```bash
git add templates/standalone/tests/index.test.js templates/standalone/tests/did-grant.test.js templates/standalone/src/__tests__/smoke.test.mts
git commit -m "$(cat <<'EOF'
test(standalone): update integration tests for new grant_type values

- grant_type=authorization → authorization_code
- grant_type=did → urn:o3co:oauth:grant-type:did (all 8 sites)

Aligns standalone template tests with RFC 6749 compliance + URN-ification
of the DID grant.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update documentation (README + env var tables)

**Files:**

- Modify: `templates/standalone/README.md`
- Modify: `templates/standalone/README.ja.md`
- Modify: `README.md` (root)
- Modify: `packages/oauth/README.md` (scan + update if needed)
- Modify: `packages/did/README.md` (add URN rationale section)

- [ ] **Step 1: Update standalone README env var tables**

In `templates/standalone/README.md` line 72:

```markdown
# Before
| `OAUTH_GRANTS_AUTHORIZATION_ENABLED` | `true` | Enable the authorization code grant type |

# After
| `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` | `true` | Enable the authorization code grant type |
```

Same for `templates/standalone/README.ja.md` line 72:

```markdown
# Before
| `OAUTH_GRANTS_AUTHORIZATION_ENABLED` | `true` | authorization code グラントタイプを有効化 |

# After
| `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` | `true` | authorization code グラントタイプを有効化 |
```

Also scan both files for `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` and rename to `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256` if present.

- [ ] **Step 2: Update root `README.md`**

Run: `grep -n "OAUTH_GRANTS_AUTHORIZATION\|grant_type=did\b" README.md`
Note the lines.

For each line:

- `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
- ASCII diagram / examples using `grant_type=did` → `grant_type=urn:o3co:oauth:grant-type:did` (prefer full URN in examples so readers understand the actual wire value; if the diagram has line-length constraints, wrap as appropriate)

- [ ] **Step 3: Scan `packages/oauth/README.md`**

Run: `grep -n "\"authorization\"\|grant_type=authorization\b\|OAUTH_GRANTS_AUTHORIZATION\b" packages/oauth/README.md`

For any match that is about the grant wire value or config (not about the English word "authorization"), update per previous tasks. Most existing text should already say "authorization_code" per prior F-series work; just confirm and fix if any stragglers exist.

- [ ] **Step 4: Update `packages/did/README.md` — add URN section**

At an appropriate place in `packages/did/README.md` (typically after the intro / before "Installation"), add:

```markdown
## Grant Type URN

The DID grant is registered under the fixed URN:

```

```text
urn:o3co:oauth:grant-type:did
```

```markdown
Clients must send this exact string as the `grant_type` parameter. The
bare string `"did"` is not supported.

### Why `urn:o3co:...`?

The DID wire protocol (`did` + `message` + `signature` form parameters)
is defined by auth.provider. Under the RFC 6755 sub-namespace ownership
model, the URN should be owned by the wire protocol definer. Here, the
`o3co` segment acts as a **wire protocol version identifier**, not a
vendor identifier — comparable to how IETF-registered grant URNs live
under `urn:ietf:params:oauth:grant-type:*`.

Consumer deployments that extend the wire protocol (e.g. to embed a
Verifiable Presentation) should define a new grant under their own URN
sub-namespace (e.g. `urn:example.com:oauth:grant-type:did-vp`) rather
than overriding this one.
```

- [ ] **Step 5: Sanity-check the markdown builds / renders**

Run: `grep -rn "\"authorization\"\|grant_type=authorization\b\|grant_type: \"did\"\|grant_type=did\b\|OAUTH_GRANTS_AUTHORIZATION[^_]" README.md templates/standalone/README.md templates/standalone/README.ja.md packages/*/README.md 2>/dev/null`
Expected: empty (all documentation references updated). If any remain, review them manually — some may be intentional (e.g. a migration note explicitly listing the old name).

- [ ] **Step 6: Commit**

```bash
git add README.md templates/standalone/README.md templates/standalone/README.ja.md packages/oauth/README.md packages/did/README.md
git commit -m "$(cat <<'EOF'
docs: update env var names + grant_type wire values

- OAUTH_GRANTS_AUTHORIZATION_* → OAUTH_GRANTS_AUTHORIZATION_CODE_*
- grant_type=authorization → authorization_code in examples
- grant_type=did → urn:o3co:oauth:grant-type:did in examples
- packages/did/README.md: add URN fixed-value section + rationale

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Update CHANGELOG

**Files:**

- Modify: `CHANGELOG.md` (root)

- [ ] **Step 1: Read current Unreleased section header**

Run: `sed -n '1,40p' CHANGELOG.md`
Identify where the `[Unreleased]` or `[0.5.0]` section begins.

- [ ] **Step 2: Add breaking change entry**

Under the Unreleased (or equivalent pre-0.5.0) section, add a new subsection `### Breaking Changes` if not already present, with these entries:

```markdown
### Breaking Changes

- **`grant_type` wire values (RFC compliance + URN-ification):**
  - `grant_type=authorization` → `grant_type=authorization_code` (RFC 6749 §4.1.3)
  - `grant_type=did` → `grant_type=urn:o3co:oauth:grant-type:did` (RFC 6755
    sub-namespace owned by auth.provider as the wire protocol definer)
  - `grant_type=session` unchanged
- **HOCON config keys + env vars:**
  - `oauth.grants.authorization { ... }` → `oauth.grants.authorization_code { ... }`
  - `OAUTH_GRANTS_AUTHORIZATION_ENABLED` → `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED`
  - `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
- **Grant policy interface (`GrantPolicyRequest.grantType`):**
  - `/oauth/authorize` flow now passes `"authorization_code"` (was `"authorization"`)
    to `grantPolicy.evaluate()`
  - `refresh_token` path unchanged
  - DID grant does not currently invoke `grantPolicy.evaluate()`; if consumers
    add policy logic for DID in the future, use the full URN
    (`"urn:o3co:oauth:grant-type:did"`) as the match value

**Migration checklist:**

1. Update client requests:
   - `grant_type=authorization` → `authorization_code`
   - `grant_type=did` → `urn:o3co:oauth:grant-type:did`
2. Update HOCON config / environment:
   - Rename `oauth.grants.authorization` → `oauth.grants.authorization_code`
   - Rename `OAUTH_GRANTS_AUTHORIZATION_*` → `OAUTH_GRANTS_AUTHORIZATION_CODE_*`
3. If implementing `GrantPolicyHookBase`:
   - Rename `case "authorization":` → `case "authorization_code":` in
     policy dispatch logic
```

- [ ] **Step 3: Verify markdown renders correctly**

Run: `sed -n '1,80p' CHANGELOG.md`
Scan visually for well-formed markdown (list indentation, code fences closed, no accidental blank lines breaking lists).

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs(changelog): document grant_type rename + config rename breaking changes

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Full test suite + lint + typecheck

**Files:** (no new modifications — verification only)

- [ ] **Step 1: Typecheck all packages**

Run: `pnpm -r typecheck`
Expected: no errors.

If errors surface, they will likely be in test files or consumer-facing examples that reference the old values. Fix inline and re-run.

- [ ] **Step 2: Lint all packages**

Run: `pnpm -r lint` (or whatever root-level lint command is defined; check `package.json` scripts)
Expected: no new lint issues introduced by this work.

- [ ] **Step 3: Run full test suite**

Run: `pnpm -r test`
Expected: PASS for all workspaces.

- [ ] **Step 4: Build all packages**

Run: `pnpm -r build`
Expected: all packages build cleanly.

- [ ] **Step 5: Verify grep finds no stragglers**

Run these commands and expect empty output (except where intentionally documenting the migration):

```bash
# Wire value stragglers
grep -rn "grant_type=authorization\b\|grant_type: \"authorization\"" packages/ templates/ --include="*.mts" --include="*.ts" --include="*.js" 2>/dev/null | grep -v __tests__ | grep -v dist | grep -v node_modules

# Registry key stragglers
grep -rn 'register("authorization",\|get("authorization")\|register("did",\|get("did")' packages/ --include="*.mts" 2>/dev/null | grep -v __tests__ | grep -v dist | grep -v node_modules

# Config key stragglers
grep -rn "grants\.authorization\b\|authorization { enabled" packages/ templates/ --include="*.mts" --include="*.ts" --include="*.conf" 2>/dev/null | grep -v node_modules | grep -v dist

# Env var stragglers
grep -rn "OAUTH_GRANTS_AUTHORIZATION_ENABLED\|OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256" . --include="*.conf" --include="*.md" --include="*.mts" --include="*.ts" 2>/dev/null | grep -v node_modules | grep -v dist | grep -v \.pnpm
```

Any hit should either (a) be fixed, or (b) be an intentional reference in CHANGELOG.md migration notes.

- [ ] **Step 6: Commit no-op marker if any fixes were needed**

If Step 5 surfaced stragglers that needed fixing, commit them:

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore: clean up remaining references to old grant_type values

Stragglers found during final grep sweep after primary rename commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

If no stragglers, skip this step.

---

## Task 9: Run /multi-agent-review

**Files:** (no modifications — review only)

- [ ] **Step 1: Invoke the multi-agent-review skill**

Trigger the `/multi-agent-review` skill on the branch `feat/grant-type-rename`.

Wait for the dual review (Claude code-reviewer + Codex) to complete.

- [ ] **Step 2: Address must-fix findings**

For each finding categorized as **must** (per the priority rule: must > should > can):

1. Fix inline in the relevant file.
2. Re-run the relevant test file to confirm the fix.
3. Commit with a descriptive message referencing the review finding.

Do not batch all fixes into a single commit — one commit per logical fix so the review trail is legible.

- [ ] **Step 3: For `should` / `can` findings**

Evaluate each against the dismiss-regime from CLAUDE.md:

- **Dismiss** only with Contract-based or Verified-empirical rationale + explicit "overturn condition"
- Otherwise, treat as must-fix

Record any dismiss decisions as a comment in the PR or as a brief note in a follow-up CHANGELOG entry.

- [ ] **Step 4: Final full test run after review fixes**

Run: `pnpm -r test && pnpm -r typecheck`
Expected: PASS.

- [ ] **Step 5: (No commit needed if no review fixes were required)**

---

## Task 10: Open PR to develop

**Files:** (no modifications — PR creation only)

- [ ] **Step 1: Push branch to remote**

```bash
git push -u origin feat/grant-type-rename
```

- [ ] **Step 2: Create PR with `gh pr create`**

```bash
gh pr create --base develop --title "feat!: grant_type RFC compliance + URN-ification (v0.5.0 #3)" --body "$(cat <<'EOF'
## Summary

- `grant_type=authorization` → `authorization_code` (RFC 6749 §4.1.3)
- `grant_type=did` → `urn:o3co:oauth:grant-type:did` (fixed URN owned by wire protocol definer)
- HOCON `oauth.grants.authorization` → `authorization_code` + env var rename
- Grant policy input value aligned with wire value at `routes.mts:466`
- Spec: `.claude/superpowers/specs/2026-04-24-grant-type-rename-design.md`

v0.5.0 Core GA must #3. Interface-freeze preparatory work. Hard break — no dual-accept.

## Test plan

- [ ] `pnpm -r test` all green
- [ ] `pnpm -r typecheck` clean
- [ ] `pnpm -r build` clean
- [ ] /multi-agent-review addressed (1 round)
- [ ] Copilot review addressed (if any)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Run `gh pr view`**

```bash
gh pr view
```

Confirm the PR is created and linked to the correct base branch.

- [ ] **Step 4: Await Copilot review**

Wait for Copilot's automated review to post comments (typical delay: 1-5 minutes after PR creation).

For each Copilot comment:

1. Evaluate per CLAUDE.md dismiss regime (must > should > can).
2. Fix must-fix items inline.
3. Reply + resolve threads using the `superpowers:github-pr-resolve` skill.

- [ ] **Step 5: Final state check**

Run: `gh pr view && gh pr checks`
Expected: PR is open, CI is green, all review threads resolved (or explicitly dismissed with rationale).

Do NOT merge — wait for the user's merge decision.

---

## Task 11: Update memory after merge

**Files:** (memory-only, no repo changes)

- [ ] **Step 1: After PR merges, update `project_v050_scope.md`**

In `/Volumes/Workspace/.claude/projects/-Volumes-Workspace-o3co-agentscopes-auth/memory/project_v050_scope.md`, mark item #3 (grant_type RFC compliance + URN-ification) as **DONE** with the merge commit SHA, merged date, and a one-line summary.

- [ ] **Step 2: Update `project_todo_next_steps.md`**

Add an entry under "Recently Completed" with merge SHA + one-line summary.
Update item 4 (v0.5.0) counter: "17 items, 2 completed" (was 1 completed).

- [ ] **Step 3: Verify `project_did_grant_migration.md` still accurate**

That memory already notes "v0.5.0 grant_type rename uses `urn:o3co:` as interim URN." No changes needed, but confirm the wording still matches reality after merge.

---
