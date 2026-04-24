# Token Exchange (RFC 8693) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 8693 Token Exchange grant for auth.provider as a new `@o3co/auth-provider-oauth-token-exchange` package, supporting on-behalf-of / delegation / scope narrowing use cases with family-cascade revocation.

**Architecture:** New standalone pnpm workspace package; exports a `GrantModule` that consumers register manually (no built-in registration, matching the federation split precedent). Subject/actor token validation goes through a pluggable `ExchangeTokenValidator` registry — ships with a built-in validator for self-issued `at+jwt`, consumer-implements validators for external JWT. Grant handler lives inside the new package; the only cross-package change is adding optional `allowedAudiences` to `Client` / `ClientEntrySchema` in core.

**Tech Stack:** TypeScript, pnpm workspaces, vitest, express (supertest), jose (JWT sign/verify), zod (config schema).

**Reference Spec:** `.claude/superpowers/specs/2026-04-24-token-exchange-design.md`

---

## File Structure

### New files (all under `packages/oauth-token-exchange/`)

- `packages/oauth-token-exchange/package.json` — workspace package manifest
- `packages/oauth-token-exchange/tsconfig.json` — extends `../../tsconfig.base.json`
- `packages/oauth-token-exchange/src/index.mts` — public export surface
- `packages/oauth-token-exchange/src/validator/types.mts` — `ExchangeTokenValidator`, `ValidatedToken`
- `packages/oauth-token-exchange/src/validator/registry.mts` — `ExchangeTokenValidatorRegistry`
- `packages/oauth-token-exchange/src/validator/selfIssuedAccessToken.mts` — built-in validator (self-issued at+jwt)
- `packages/oauth-token-exchange/src/act.mts` — `buildActClaim()` helper (nested delegation chain)
- `packages/oauth-token-exchange/src/grant.mts` — `createTokenExchangeGrant()` handler
- `packages/oauth-token-exchange/src/module.mts` — `tokenExchangeModule` (GrantModule export)
- `packages/oauth-token-exchange/src/__tests__/fixtures.mts` — shared test fixtures (keyStore, signers)
- `packages/oauth-token-exchange/src/__tests__/registry.test.mts`
- `packages/oauth-token-exchange/src/__tests__/selfIssuedAccessToken.test.mts`
- `packages/oauth-token-exchange/src/__tests__/act.test.mts`
- `packages/oauth-token-exchange/src/__tests__/grant.test.mts`
- `packages/oauth-token-exchange/src/__tests__/grant-integration.test.mts` — cross-grant scenario (authz_code → token_exchange)
- `packages/oauth-token-exchange/README.md` — usage + security notes

### Modified files

- `packages/core/src/repositories/types.mts` — add optional `allowedAudiences?: string[]` to `Client`
- `packages/core/src/repositories/InMemoryClientRepository.mts` — add `allowedAudiences` to `ClientEntrySchema` + propagate in `findById` / `authenticate`

### Unchanged (read-only dependencies)

- `packages/core/src/grants/types.mts` — `GrantContext` / `GrantHandler` / `GrantModule` / `GrantDependencies`
- `packages/core/src/grants/registry.mts` — `GrantRegistry.addModule()` (already supports `enabled: false`)
- `packages/core/src/grants/token.mts` — `generateToken()`, `generateTokenResponse()`
- `packages/core/src/refresh/types.mts` — `RefreshTokenStoreBase.isFamilyRevoked`
- `packages/core/src/policy/types.mts` — `GrantPolicyHookBase`, `GrantPolicyRequest`, `GrantPolicyDecision`
- `packages/core/src/keys/KeyStore.mts` — `KeyStore` signing / verification

---

## Task 1: Scaffold the new package

**Files:**
- Create: `packages/oauth-token-exchange/package.json`
- Create: `packages/oauth-token-exchange/tsconfig.json`
- Create: `packages/oauth-token-exchange/src/index.mts`
- Create: `packages/oauth-token-exchange/README.md`

- [ ] **Step 1: Create package.json**

Write `packages/oauth-token-exchange/package.json`:

```json
{
	"name": "@o3co/auth-provider-oauth-token-exchange",
	"description": "RFC 8693 Token Exchange grant for auth.provider",
	"version": "0.0.0",
	"license": "Apache-2.0",
	"type": "module",
	"exports": {
		".": {
			"import": "./dist/index.mjs",
			"types": "./dist/index.d.mts"
		}
	},
	"files": [
		"dist",
		"README.md",
		"LICENSE"
	],
	"repository": {
		"type": "git",
		"url": "https://github.com/o3co/auth.provider.git",
		"directory": "packages/oauth-token-exchange"
	},
	"imports": {
		"#/*": {
			"development": "./src/*",
			"default": "./dist/*"
		}
	},
	"scripts": {
		"prebuild": "rimraf dist",
		"build": "tsc",
		"typecheck": "tsc --noEmit",
		"test": "vitest run",
		"test:coverage": "vitest run --coverage"
	},
	"dependencies": {
		"jose": "^5.9.6",
		"zod": "^3.23.8"
	},
	"peerDependencies": {
		"@o3co/auth-provider-core": "^0.0.0"
	},
	"devDependencies": {
		"@o3co/auth-provider-core": "workspace:*",
		"@vitest/coverage-v8": "^4.1.2",
		"typescript": "^5.9.3",
		"vitest": "^4.1.2"
	}
}
```

Pin versions to match existing packages. Check `packages/oauth/package.json` for the authoritative `jose` / `zod` versions and copy — if they differ from the above, use those.

- [ ] **Step 2: Create tsconfig.json**

Write `packages/oauth-token-exchange/tsconfig.json`:

```json
{
	"extends": "../../tsconfig.base.json",
	"compilerOptions": {
		"rootDir": "./src",
		"outDir": "./dist/",
		"paths": {
			"#/*": ["./src/*"]
		}
	},
	"include": ["src/**/*"],
	"exclude": ["node_modules", "dist", "src/**/__tests__/**"]
}
```

- [ ] **Step 3: Create empty src/index.mts with Apache 2.0 header**

Write `packages/oauth-token-exchange/src/index.mts`:

```ts
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

export {};
```

This is intentionally empty — later tasks add exports.

- [ ] **Step 4: Create minimal README.md placeholder**

Write `packages/oauth-token-exchange/README.md`:

```markdown
# @o3co/auth-provider-oauth-token-exchange

RFC 8693 Token Exchange grant for auth.provider. See design spec at
`.claude/superpowers/specs/2026-04-24-token-exchange-design.md`.

Full usage documentation is added in Task 11.
```

- [ ] **Step 5: Install workspace dependencies**

Run: `pnpm install`

Expected output: a line like `+ @o3co/auth-provider-oauth-token-exchange 0.0.0 <-- packages/oauth-token-exchange` (new workspace package linked).

If pnpm complains about missing `LICENSE`, copy from another package:

```bash
cp packages/oauth/LICENSE packages/oauth-token-exchange/LICENSE
```

- [ ] **Step 6: Verify typecheck passes on the skeleton**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0 with no output.

- [ ] **Step 7: Commit**

```bash
git add packages/oauth-token-exchange/
git commit -m "feat(token-exchange): scaffold @o3co/auth-provider-oauth-token-exchange package"
```

---

## Task 2: Extend Client with allowedAudiences (core change)

**Files:**
- Modify: `packages/core/src/repositories/types.mts`
- Modify: `packages/core/src/repositories/InMemoryClientRepository.mts`
- Test: `packages/core/src/repositories/__tests__/InMemoryClientRepository.test.mts`

- [ ] **Step 1: Write failing test for `allowedAudiences` default**

Open `packages/core/src/repositories/__tests__/InMemoryClientRepository.test.mts` and append (before the final closing brace/describe, follow existing structure):

```ts
it("exposes allowedAudiences via findById (empty array when omitted)", async () => {
	const repo = new InMemoryClientRepository(
		new Map([
			[
				"client-a",
				{
					clientSecret: "s",
					allowedRedirectUris: [],
					allowedScopes: [],
				},
			],
		]),
	);
	const client = await repo.findById("client-a");
	expect(client?.allowedAudiences).toEqual([]);
});

it("exposes allowedAudiences via findById (preserves configured values)", async () => {
	const repo = new InMemoryClientRepository(
		new Map([
			[
				"client-b",
				{
					clientSecret: "s",
					allowedRedirectUris: [],
					allowedScopes: [],
					allowedAudiences: ["billing-service", "inventory-service"],
				},
			],
		]),
	);
	const client = await repo.findById("client-b");
	expect(client?.allowedAudiences).toEqual(["billing-service", "inventory-service"]);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @o3co/auth-provider-core test -- InMemoryClientRepository`

Expected: the two new tests FAIL (`allowedAudiences` undefined, or zod rejects unknown key because `ClientEntrySchema.strict()`).

- [ ] **Step 3: Add `allowedAudiences` to `Client` type**

Edit `packages/core/src/repositories/types.mts`. After line 21 (`allowedScopes: string[];`), add:

```ts
	/**
	 * Audience URIs that this client may request in Token Exchange (RFC 8693)
	 * `audience` parameter. Empty or undefined means only the client's own
	 * clientId is allowed as audience. Not used outside Token Exchange.
	 */
	allowedAudiences?: string[];
```

- [ ] **Step 4: Add `allowedAudiences` to `ClientEntrySchema`**

Edit `packages/core/src/repositories/InMemoryClientRepository.mts`. Inside the `ClientEntrySchema` zod object (around line 60-80), add:

```ts
		allowedAudiences: z.array(z.string()).default([]),
```

Place it immediately after the `allowedScopes` line for locality.

- [ ] **Step 5: Propagate `allowedAudiences` in `findById` and `authenticate`**

In the same file (`InMemoryClientRepository.mts`), both `findById` (around line 95) and `authenticate` (around line 135) build the returned `PublicClient` object. Add:

```ts
			allowedAudiences: entry.allowedAudiences,
```

Add it in both return statements, right after `allowedScopes: entry.allowedScopes,`.

- [ ] **Step 6: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-core test -- InMemoryClientRepository`

Expected: all tests PASS including the two new ones.

Also run the full core test suite to catch any regression:

Run: `pnpm --filter @o3co/auth-provider-core test`

Expected: all PASS.

- [ ] **Step 7: Verify core typecheck passes**

Run: `pnpm --filter @o3co/auth-provider-core typecheck`

Expected: exits 0.

- [ ] **Step 8: Commit**

```bash
git add packages/core/src/repositories/types.mts packages/core/src/repositories/InMemoryClientRepository.mts packages/core/src/repositories/__tests__/InMemoryClientRepository.test.mts
git commit -m "feat(core): add optional Client.allowedAudiences for Token Exchange audience narrowing"
```

---

## Task 3: ExchangeTokenValidator interface + Registry

**Files:**
- Create: `packages/oauth-token-exchange/src/validator/types.mts`
- Create: `packages/oauth-token-exchange/src/validator/registry.mts`
- Create: `packages/oauth-token-exchange/src/__tests__/registry.test.mts`

- [ ] **Step 1: Write failing test for Registry**

Write `packages/oauth-token-exchange/src/__tests__/registry.test.mts`:

```ts
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

import { describe, expect, it } from "vitest";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import type { ExchangeTokenValidator } from "#/validator/types.mjs";

const stubValidator = (tokenType: string): ExchangeTokenValidator => ({
	tokenType,
	async validate() {
		return null;
	},
});

describe("ExchangeTokenValidatorRegistry", () => {
	it("returns undefined for unregistered token type", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBeUndefined();
	});

	it("returns the registered validator by tokenType", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v = stubValidator("urn:ietf:params:oauth:token-type:access_token");
		registry.register("urn:ietf:params:oauth:token-type:access_token", v);
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v);
	});

	it("overwrites an existing registration on re-register", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v1 = stubValidator("urn:ietf:params:oauth:token-type:access_token");
		const v2 = stubValidator("urn:ietf:params:oauth:token-type:access_token");
		registry.register("urn:ietf:params:oauth:token-type:access_token", v1);
		registry.register("urn:ietf:params:oauth:token-type:access_token", v2);
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v2);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- registry`

Expected: FAIL (module `#/validator/registry.mjs` not found).

- [ ] **Step 3: Create validator/types.mts**

Write `packages/oauth-token-exchange/src/validator/types.mts`:

```ts
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

/**
 * Role of a token within a Token Exchange request.
 * - "subject": the token being exchanged (`subject_token`)
 * - "actor":   the token of the party performing the exchange (`actor_token`)
 */
export interface ExchangeTokenValidationContext {
	role: "subject" | "actor";
}

/**
 * Validates a token presented in a Token Exchange request.
 *
 * Consumers register one validator per `subject_token_type` / `actor_token_type`
 * URI. Returning `null` signals a validation failure — the grant handler will
 * respond with `invalid_grant`. Throwing signals an infrastructure failure
 * (e.g. Redis unavailable) — the grant handler will respond with
 * `temporarily_unavailable` (503).
 */
export interface ExchangeTokenValidator {
	readonly tokenType: string;
	validate(
		token: string,
		context: ExchangeTokenValidationContext,
	): Promise<ValidatedToken | null>;
}

/**
 * Structured representation of a validated exchange token.
 * `familyId` is populated only for self-issued access_tokens that carry a
 * `family_id` claim (used for cascading revoke inheritance).
 */
export interface ValidatedToken {
	sub: string;
	scope?: string;
	aud?: string | string[];
	familyId?: string;
	act?: Record<string, unknown>;
	claims: Record<string, unknown>;
}
```

- [ ] **Step 4: Create validator/registry.mts**

Write `packages/oauth-token-exchange/src/validator/registry.mts`:

```ts
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

import type { ExchangeTokenValidator } from "./types.mjs";

/**
 * Mutable registry keyed by RFC 8693 `token_type` URI. Used by the Token
 * Exchange grant handler to dispatch `subject_token` / `actor_token`
 * validation.
 */
export class ExchangeTokenValidatorRegistry {
	private validators = new Map<string, ExchangeTokenValidator>();

	register(tokenType: string, validator: ExchangeTokenValidator): void {
		this.validators.set(tokenType, validator);
	}

	get(tokenType: string): ExchangeTokenValidator | undefined {
		return this.validators.get(tokenType);
	}
}
```

- [ ] **Step 5: Run test to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- registry`

Expected: all three tests PASS.

- [ ] **Step 6: Export from package index**

Edit `packages/oauth-token-exchange/src/index.mts` — replace `export {};` with:

```ts
export type {
	ExchangeTokenValidationContext,
	ExchangeTokenValidator,
	ValidatedToken,
} from "./validator/types.mjs";
export { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";
```

- [ ] **Step 7: Verify typecheck**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0.

- [ ] **Step 8: Commit**

```bash
git add packages/oauth-token-exchange/src/validator/ packages/oauth-token-exchange/src/index.mts packages/oauth-token-exchange/src/__tests__/registry.test.mts
git commit -m "feat(token-exchange): add ExchangeTokenValidator interface + Registry"
```

---

## Task 4: Self-issued access_token validator (built-in)

**Files:**
- Create: `packages/oauth-token-exchange/src/validator/selfIssuedAccessToken.mts`
- Create: `packages/oauth-token-exchange/src/__tests__/fixtures.mts`
- Create: `packages/oauth-token-exchange/src/__tests__/selfIssuedAccessToken.test.mts`

- [ ] **Step 1: Create shared test fixtures**

Write `packages/oauth-token-exchange/src/__tests__/fixtures.mts`:

```ts
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

import { createSecretKey } from "node:crypto";
import {
	createSymmetricKeyStore,
	type KeyStore,
	type RefreshTokenStoreBase,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";

export const SECRET = "test-secret-at-least-32-chars!!";
export const keyStore: KeyStore = createSymmetricKeyStore(SECRET);
export const secretKey = createSecretKey(Buffer.from(SECRET));

export const ISSUER = "https://auth.example";

export async function signSelfIssuedAccessToken(
	claims: Record<string, unknown>,
	options: { expiresIn?: string; typ?: string } = {},
): Promise<string> {
	const { expiresIn = "1h", typ = "at+jwt" } = options;
	return new SignJWT({
		sub: "user-1",
		scope: "read",
		iss: ISSUER,
		aud: "client-a",
		...claims,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ })
		.setIssuedAt()
		.setExpirationTime(expiresIn)
		.sign(secretKey);
}

export function makeRefreshStore(
	overrides: Partial<RefreshTokenStoreBase> = {},
): RefreshTokenStoreBase {
	return {
		kind: "fixture",
		async rotate() {
			return { outcome: "rotated" };
		},
		async isFamilyRevoked() {
			return false;
		},
		async revokeFamily() {},
		...overrides,
	};
}
```

- [ ] **Step 2: Write failing tests for selfIssuedAccessToken validator**

Write `packages/oauth-token-exchange/src/__tests__/selfIssuedAccessToken.test.mts`:

```ts
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

import { describe, expect, it, vi } from "vitest";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import {
	ISSUER,
	keyStore,
	makeRefreshStore,
	signSelfIssuedAccessToken,
} from "./fixtures.mjs";

describe("createSelfIssuedAccessTokenValidator", () => {
	const validator = (overrides = {}) =>
		createSelfIssuedAccessTokenValidator({
			keyStore,
			refreshTokenStore: makeRefreshStore(),
			issuer: ISSUER,
			...overrides,
		});

	it("accepts a valid self-issued at+jwt and returns claims", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.sub).toBe("user-1");
		expect(result?.scope).toBe("read");
		expect(result?.familyId).toBe("fam-1");
	});

	it("returns null for a tampered signature", async () => {
		const token = (await signSelfIssuedAccessToken({})).slice(0, -4) + "AAAA";
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null for an expired token", async () => {
		const token = await signSelfIssuedAccessToken({}, { expiresIn: "-1s" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when issuer does not match the configured issuer", async () => {
		const token = await signSelfIssuedAccessToken({ iss: "https://other.example" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when family is revoked", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-revoked" });
		const store = makeRefreshStore({
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		});
		const v = validator({ refreshTokenStore: store });
		expect(await v.validate(token, { role: "subject" })).toBeNull();
		expect(store.isFamilyRevoked).toHaveBeenCalledWith("fam-revoked");
	});

	it("throws when isFamilyRevoked throws (runtime unavailable)", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const store = makeRefreshStore({
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("redis down")),
		});
		const v = validator({ refreshTokenStore: store });
		await expect(v.validate(token, { role: "subject" })).rejects.toThrow("redis down");
	});

	it("accepts a token without family_id claim (legacy) when refreshTokenStore is present", async () => {
		const token = await signSelfIssuedAccessToken({});
		const store = makeRefreshStore();
		const v = validator({ refreshTokenStore: store });
		const result = await v.validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.familyId).toBeUndefined();
	});

	it("preserves existing act claim on the token", async () => {
		const token = await signSelfIssuedAccessToken({ act: { sub: "service-upstream" } });
		const result = await validator().validate(token, { role: "subject" });
		expect(result?.act).toEqual({ sub: "service-upstream" });
	});

	it("exposes tokenType as the access_token URI", () => {
		expect(validator().tokenType).toBe("urn:ietf:params:oauth:token-type:access_token");
	});
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- selfIssuedAccessToken`

Expected: FAIL (module not found).

- [ ] **Step 4: Implement selfIssuedAccessToken validator**

Write `packages/oauth-token-exchange/src/validator/selfIssuedAccessToken.mts`:

```ts
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

import type { KeyStore, RefreshTokenStoreBase } from "@o3co/auth-provider-core";
import { decodeProtectedHeader, jwtVerify } from "jose";
import type { ExchangeTokenValidator, ValidatedToken } from "./types.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface CreateSelfIssuedAccessTokenValidatorOptions {
	keyStore: KeyStore;
	refreshTokenStore?: RefreshTokenStoreBase;
	issuer?: string;
}

/**
 * Built-in validator for RFC 8693 subject_token_type=access_token when the
 * token was issued by this auth.provider instance. Verifies JWT signature
 * (KeyStore), standard claims (exp via jose), issuer match, and — when a
 * refreshTokenStore is wired — family_id cascading revoke.
 *
 * Throws on infrastructure failures (store unavailable). Returns null on
 * validation failures (bad signature, expired, revoked, issuer mismatch).
 */
export function createSelfIssuedAccessTokenValidator(
	options: CreateSelfIssuedAccessTokenValidatorOptions,
): ExchangeTokenValidator {
	const { keyStore, refreshTokenStore, issuer } = options;

	return {
		tokenType: ACCESS_TOKEN_TYPE,
		async validate(token: string): Promise<ValidatedToken | null> {
			let payload: Record<string, unknown>;
			try {
				const header = decodeProtectedHeader(token);
				const key = await keyStore.getVerificationKey(
					header.kid ?? keyStore.getSigningKidFallback(),
				);
				const verified = await jwtVerify(token, key);
				payload = verified.payload as Record<string, unknown>;
			} catch {
				return null;
			}

			if (issuer && payload.iss !== issuer) {
				return null;
			}

			const familyId = typeof payload.family_id === "string" ? payload.family_id : undefined;

			if (familyId && refreshTokenStore) {
				// Throws on runtime failure — grant handler converts to 503.
				const revoked = await refreshTokenStore.isFamilyRevoked(familyId);
				if (revoked) return null;
			}

			const result: ValidatedToken = {
				sub: String(payload.sub ?? ""),
				claims: payload,
			};
			if (typeof payload.scope === "string") result.scope = payload.scope;
			if (typeof payload.aud === "string" || Array.isArray(payload.aud)) {
				result.aud = payload.aud as string | string[];
			}
			if (familyId) result.familyId = familyId;
			if (payload.act && typeof payload.act === "object") {
				result.act = payload.act as Record<string, unknown>;
			}
			return result;
		},
	};
}
```

- [ ] **Step 5: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- selfIssuedAccessToken`

Expected: all 9 tests PASS.

- [ ] **Step 6: Export factory from package index**

Edit `packages/oauth-token-exchange/src/index.mts` — append:

```ts
export {
	type CreateSelfIssuedAccessTokenValidatorOptions,
	createSelfIssuedAccessTokenValidator,
} from "./validator/selfIssuedAccessToken.mjs";
```

- [ ] **Step 7: Verify typecheck + commit**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0.

```bash
git add packages/oauth-token-exchange/src/validator/selfIssuedAccessToken.mts packages/oauth-token-exchange/src/__tests__/fixtures.mts packages/oauth-token-exchange/src/__tests__/selfIssuedAccessToken.test.mts packages/oauth-token-exchange/src/index.mts
git commit -m "feat(token-exchange): add built-in self-issued access_token validator with family revoke check"
```

---

## Task 5: `act` claim builder

**Files:**
- Create: `packages/oauth-token-exchange/src/act.mts`
- Create: `packages/oauth-token-exchange/src/__tests__/act.test.mts`

- [ ] **Step 1: Write failing tests for buildActClaim**

Write `packages/oauth-token-exchange/src/__tests__/act.test.mts`:

```ts
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

import { describe, expect, it } from "vitest";
import { buildActClaim } from "#/act.mjs";
import type { ValidatedToken } from "#/validator/types.mjs";

const tok = (overrides: Partial<ValidatedToken> = {}): ValidatedToken => ({
	sub: "user-1",
	claims: {},
	...overrides,
});

describe("buildActClaim", () => {
	it("returns undefined when no actor_token is present (impersonation)", () => {
		expect(buildActClaim({ subject: tok({ sub: "alice" }), actor: undefined })).toBeUndefined();
	});

	it("does NOT inherit subject.act when no actor_token is present", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice", act: { sub: "upstream" } }),
			actor: undefined,
		});
		expect(result).toBeUndefined();
	});

	it("returns { sub: <actor.sub> } for simple delegation", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice" }),
			actor: tok({ sub: "service-a" }),
		});
		expect(result).toEqual({ sub: "service-a" });
	});

	it("nests subject.act inside new act for multi-step delegation", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice", act: { sub: "service-a" } }),
			actor: tok({ sub: "service-b" }),
		});
		expect(result).toEqual({ sub: "service-b", act: { sub: "service-a" } });
	});

	it("preserves deep nested act chain from subject", () => {
		const result = buildActClaim({
			subject: tok({
				sub: "alice",
				act: { sub: "service-a", act: { sub: "service-upstream" } },
			}),
			actor: tok({ sub: "service-b" }),
		});
		expect(result).toEqual({
			sub: "service-b",
			act: { sub: "service-a", act: { sub: "service-upstream" } },
		});
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- act`

Expected: FAIL (module not found).

- [ ] **Step 3: Implement buildActClaim**

Write `packages/oauth-token-exchange/src/act.mts`:

```ts
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

import type { ValidatedToken } from "./validator/types.mjs";

/**
 * Build the `act` claim for the token being issued, per RFC 8693 §4.1.
 *
 * Canonical rules:
 * - No actor_token → no `act` on the issued token (impersonation, no trace).
 *                    We do NOT inherit `subject.act`: absence of actor_token
 *                    means the caller is not claiming to delegate for anyone.
 * - Actor provided  → `act.sub = <actor.sub>`. If the subject already had an
 *                     `act` chain, it is nested as `act.act` to preserve the
 *                     full delegation history.
 */
export function buildActClaim(args: {
	subject: ValidatedToken;
	actor: ValidatedToken | undefined;
}): Record<string, unknown> | undefined {
	const { subject, actor } = args;
	if (!actor) return undefined;

	const result: Record<string, unknown> = { sub: actor.sub };
	if (subject.act) {
		result.act = subject.act;
	}
	return result;
}
```

- [ ] **Step 4: Run test to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- act`

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/oauth-token-exchange/src/act.mts packages/oauth-token-exchange/src/__tests__/act.test.mts
git commit -m "feat(token-exchange): add buildActClaim helper for RFC 8693 §4.1 delegation chain"
```

---

## Task 6: Grant handler — request parse, unsupported checks

**Files:**
- Create: `packages/oauth-token-exchange/src/grant.mts`
- Create: `packages/oauth-token-exchange/src/__tests__/grant.test.mts`

This task bootstraps the handler and covers the RFC 8693 error surface for malformed / unsupported requests. Happy-path and downstream checks come in Tasks 7-9.

- [ ] **Step 1: Write failing tests for request parse + unsupported errors**

Write `packages/oauth-token-exchange/src/__tests__/grant.test.mts`:

```ts
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

import type {
	AppConfig,
	ClientRepository,
	GrantContext,
	PublicClient,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeRefreshStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

const mockConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

const publicClient = (overrides: Partial<PublicClient> = {}): PublicClient => ({
	clientId: "client-a",
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
	...overrides,
});

const mockClientRepository = (client: PublicClient | null = publicClient()): ClientRepository => ({
	findById: async (id) => (id === client?.clientId ? client : null),
	authenticate: async (id, _secret) => (id === client?.clientId ? client : null),
});

function buildGrant(
	overrides: {
		validatorRegistry?: ExchangeTokenValidatorRegistry;
		clientRepository?: ClientRepository;
		refreshTokenStore?: ReturnType<typeof makeRefreshStore> | undefined;
		config?: AppConfig;
	} = {},
) {
	const registry = overrides.validatorRegistry ?? new ExchangeTokenValidatorRegistry();
	const refreshStore =
		overrides.refreshTokenStore === undefined ? makeRefreshStore() : overrides.refreshTokenStore;
	if (!overrides.validatorRegistry) {
		registry.register(
			ACCESS_TOKEN_TYPE,
			createSelfIssuedAccessTokenValidator({
				keyStore,
				refreshTokenStore: refreshStore,
				issuer: ISSUER,
			}),
		);
	}
	return createTokenExchangeGrant({
		config: overrides.config ?? mockConfig,
		keyStore,
		refreshTokenStore: refreshStore,
		validatorRegistry: registry,
		clientRepository: overrides.clientRepository ?? mockClientRepository(),
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
});

describe("createTokenExchangeGrant — request errors", () => {
	it("returns invalid_request when subject_token is missing", async () => {
		const g = buildGrant();
		const { result } = await g.handle(
			ctx({ client_id: "client-a", subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when subject_token_type is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(ctx({ client_id: "client-a", subject_token: token }));
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when client_id is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({ subject_token: token, subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_client when client cannot be authenticated", async () => {
		const g = buildGrant({ clientRepository: mockClientRepository(null) });
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "unknown",
				client_secret: "x",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 401, error: "invalid_client" });
	});

	it("returns unsupported_token_type when subject_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when requested_token_type is not access_token", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when actor_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: "any",
				actor_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: FAIL (`createTokenExchangeGrant` not found).

- [ ] **Step 3: Implement grant.mts — request parse + unsupported checks ONLY**

Write `packages/oauth-token-exchange/src/grant.mts`:

```ts
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

import type {
	ClientRepository,
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
} from "@o3co/auth-provider-core";
import type { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface TokenExchangeDependencies extends GrantDependencies {
	validatorRegistry: ExchangeTokenValidatorRegistry;
	clientRepository: ClientRepository;
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { validatorRegistry, clientRepository } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const body = ctx.body as Record<string, unknown>;

			const subjectToken = typeof body.subject_token === "string" ? body.subject_token : null;
			const subjectTokenType =
				typeof body.subject_token_type === "string" ? body.subject_token_type : null;
			const clientId = typeof body.client_id === "string" ? body.client_id : null;
			const clientSecret =
				typeof body.client_secret === "string" ? body.client_secret : null;
			const actorToken = typeof body.actor_token === "string" ? body.actor_token : null;
			const actorTokenType =
				typeof body.actor_token_type === "string" ? body.actor_token_type : null;
			const requestedTokenType =
				typeof body.requested_token_type === "string" ? body.requested_token_type : null;

			if (!subjectToken || !subjectTokenType || !clientId) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "subject_token, subject_token_type, client_id are required",
					},
				};
			}

			// Client authentication: confidential clients send client_secret, public
			// clients omit it. Either way, the client must exist.
			const client =
				clientSecret !== null
					? await clientRepository.authenticate(clientId, clientSecret)
					: await clientRepository.findById(clientId);
			if (!client) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "client authentication failed",
					},
				};
			}

			if (requestedTokenType !== null && requestedTokenType !== ACCESS_TOKEN_TYPE) {
				return {
					result: {
						status: 400,
						error: "unsupported_token_type",
						errorDescription: `requested_token_type "${requestedTokenType}" is not supported`,
					},
				};
			}

			const subjectValidator = validatorRegistry.get(subjectTokenType);
			if (!subjectValidator) {
				return {
					result: {
						status: 400,
						error: "unsupported_token_type",
						errorDescription: `subject_token_type "${subjectTokenType}" is not supported`,
					},
				};
			}

			if (actorToken !== null) {
				if (actorTokenType === null) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "actor_token_type is required when actor_token is provided",
						},
					};
				}
				const actorValidator = validatorRegistry.get(actorTokenType);
				if (!actorValidator) {
					return {
						result: {
							status: 400,
							error: "unsupported_token_type",
							errorDescription: `actor_token_type "${actorTokenType}" is not supported`,
						},
					};
				}
			}

			// Subsequent steps (validate tokens, narrow scope/audience, call policy
			// hook, mint new token) are added in Tasks 7-9.
			return {
				result: {
					status: 501,
					error: "not_implemented",
					errorDescription: "Token Exchange handler is partially implemented",
				},
			};
		},
	};
}

export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE, ACCESS_TOKEN_TYPE };
```

- [ ] **Step 4: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: all 7 tests PASS.

- [ ] **Step 5: Verify typecheck**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0.

- [ ] **Step 6: Commit**

```bash
git add packages/oauth-token-exchange/src/grant.mts packages/oauth-token-exchange/src/__tests__/grant.test.mts
git commit -m "feat(token-exchange): grant handler stub with request parse + unsupported error surface"
```

---

## Task 7: Grant handler — token validation + scope/audience narrowing

**Files:**
- Modify: `packages/oauth-token-exchange/src/grant.mts`
- Modify: `packages/oauth-token-exchange/src/__tests__/grant.test.mts`

- [ ] **Step 1: Append failing tests for validation + narrowing**

Append to `packages/oauth-token-exchange/src/__tests__/grant.test.mts` (after the existing describe block):

```ts
describe("createTokenExchangeGrant — token validation", () => {
	it("returns invalid_grant when subject_token signature is invalid", async () => {
		const g = buildGrant();
		const token = (await signSelfIssuedAccessToken({})).slice(0, -4) + "AAAA";
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("returns invalid_grant/family_revoked when subject family is revoked", async () => {
		const store = makeRefreshStore({
			isFamilyRevoked: async (id) => id === "fam-bad",
		});
		const g = buildGrant({ refreshTokenStore: store });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-bad" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "family_revoked",
		});
	});

	it("returns invalid_grant when refreshTokenStore is not wired (fail-closed)", async () => {
		// biome-ignore lint/suspicious/noExplicitAny: test-only narrowing
		const g = buildGrant({ refreshTokenStore: undefined as any });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("returns temporarily_unavailable (503) when validator throws (runtime store failure)", async () => {
		const store = makeRefreshStore({
			isFamilyRevoked: async () => {
				throw new Error("redis down");
			},
		});
		const g = buildGrant({ refreshTokenStore: store });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("returns invalid_grant when actor_token fails validation", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const badActor = (await signSelfIssuedAccessToken({ sub: "svc-a" })).slice(0, -4) + "AAAA";
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: badActor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});
});

describe("createTokenExchangeGrant — narrowing checks", () => {
	it("returns invalid_scope when requested scope is a superset of subject scope", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_scope" });
	});

	it("returns invalid_target when audience is not in allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "inventory",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("accepts audience when it matches clientId even without allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "client-a",
			}),
		);
		// Narrowing passes — later tasks add minting. For now the handler still
		// returns 501 (not_implemented) from the stub.
		expect(result).toMatchObject({ status: 501 });
	});

	it("accepts multi-value audience when all entries are in allowlist ∪ {clientId}", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: ["billing", "inventory"],
			}),
		);
		expect(result).toMatchObject({ status: 501 });
	});
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: the new tests FAIL (stub still returns 501 for all inputs past the unsupported checks).

- [ ] **Step 3: Replace the stub body with validation + narrowing logic**

Edit `packages/oauth-token-exchange/src/grant.mts`. Replace the final return block (the 501 stub, starting with `// Subsequent steps (...)`) with:

```ts
			const subjectValidated = await (async () => {
				try {
					return await subjectValidator.validate(subjectToken, { role: "subject" });
				} catch {
					return "runtime_error" as const;
				}
			})();
			if (subjectValidated === "runtime_error") {
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "subject_token validation store unavailable",
					},
				};
			}
			if (!subjectValidated) {
				// Distinguish family-revoked rejection (which only the self-issued
				// validator can emit) from other validation failures. Self-issued
				// validator returns null both for bad-signature AND revoked family —
				// we re-check the family here when a refresh store is wired so the
				// errorDescription accurately reports the failure mode for operators.
				// For non-self-issued validators (external JWT), the errorDescription
				// stays generic.
				// Note: fail-closed when refreshTokenStore is not wired is enforced
				// below; here we only handle the post-wire case.
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "subject_token validation failed",
					},
				};
			}

			// Fail-closed: the self-issued validator silently skips the family check
			// when refreshTokenStore is absent, but Token Exchange must not issue
			// tokens whose revocation cannot be observed (spec §7.2 state 1).
			if (
				subjectValidated.familyId &&
				!deps.refreshTokenStore &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "refresh token store not configured (revocation cannot be verified)",
					},
				};
			}

			// Re-surface family_revoked for operators by consulting the store directly
			// when a family_id was present. isFamilyRevoked is idempotent and cheap.
			if (
				subjectValidated.familyId &&
				deps.refreshTokenStore &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				let revoked: boolean;
				try {
					revoked = await deps.refreshTokenStore.isFamilyRevoked(subjectValidated.familyId);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "refresh token store unavailable",
						},
					};
				}
				if (revoked) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "family_revoked",
						},
					};
				}
			}

			let actorValidated: typeof subjectValidated | null = null;
			if (actorToken !== null && actorTokenType !== null) {
				const actorValidator = validatorRegistry.get(actorTokenType);
				// actorValidator existence already checked above, but narrow again.
				if (!actorValidator) {
					return {
						result: {
							status: 400,
							error: "unsupported_token_type",
							errorDescription: `actor_token_type "${actorTokenType}" is not supported`,
						},
					};
				}
				try {
					actorValidated = await actorValidator.validate(actorToken, { role: "actor" });
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "actor_token validation store unavailable",
						},
					};
				}
				if (!actorValidated) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "actor_token validation failed",
						},
					};
				}
			}

			// Scope narrowing: requested scope ⊆ subject scope.
			const subjectScope = subjectValidated.scope?.split(" ").filter(Boolean) ?? [];
			const requestedScopeStr = typeof body.scope === "string" ? body.scope : null;
			const requestedScope = requestedScopeStr?.split(" ").filter(Boolean) ?? null;
			if (requestedScope) {
				const subjectScopeSet = new Set(subjectScope);
				for (const s of requestedScope) {
					if (!subjectScopeSet.has(s)) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `scope "${s}" is not in subject_token scope`,
							},
						};
					}
				}
			}

			// Audience narrowing: requested audience ⊆ client.allowedAudiences ∪ {clientId}.
			const requestedAudience = normalizeArrayParam(body.audience);
			const requestedResource = normalizeArrayParam(body.resource);
			if (requestedAudience) {
				const allow = new Set([
					...(client.allowedAudiences ?? []),
					client.clientId,
				]);
				for (const aud of requestedAudience) {
					if (!allow.has(aud)) {
						return {
							result: {
								status: 400,
								error: "invalid_target",
								errorDescription: `audience "${aud}" is not allowed for this client`,
							},
						};
					}
				}
			}

			// Minting + policy hook + act-claim construction come in Tasks 8-9.
			void actorValidated;
			void requestedResource;
			return {
				result: {
					status: 501,
					error: "not_implemented",
					errorDescription: "Token Exchange minting is not yet implemented",
				},
			};
```

Also, at the bottom of the file (before the trailing `export { ... }` line), add the helper:

```ts
function normalizeArrayParam(value: unknown): string[] | null {
	if (value === undefined || value === null || value === "") return null;
	if (Array.isArray(value)) return value.map(String);
	return [String(value)];
}
```

- [ ] **Step 4: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: all tests in both describe blocks PASS. The three narrowing-passes tests still expect `status: 501` from the stub — that is correct for this task.

- [ ] **Step 5: Verify typecheck**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0.

- [ ] **Step 6: Commit**

```bash
git add packages/oauth-token-exchange/src/grant.mts packages/oauth-token-exchange/src/__tests__/grant.test.mts
git commit -m "feat(token-exchange): add subject/actor validation + scope/audience narrowing"
```

---

## Task 8: Grant handler — policy hook + mint new access_token

**Files:**
- Modify: `packages/oauth-token-exchange/src/grant.mts`
- Modify: `packages/oauth-token-exchange/src/__tests__/grant.test.mts`

This replaces the 501 stub with the final minting logic. After this task the `status: 501` expectations in Task 7 tests become stale — they're updated as part of the same step.

- [ ] **Step 1: Update Task 7 tests — change the two `status: 501` assertions**

Edit `packages/oauth-token-exchange/src/__tests__/grant.test.mts`. Replace the two `expect(result).toMatchObject({ status: 501 });` assertions in the narrowing-checks describe block with richer happy-path checks:

For the "accepts audience when it matches clientId" test, replace with:

```ts
		expect(result).toMatchObject({ status: 200 });
		if (result.status === 200) {
			expect(result.tokens.access_token).toBeDefined();
			expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
			expect(result.tokens.token_type).toBe("Bearer");
			expect(result.tokens.refresh_token).toBeFalsy();
		}
```

For the "accepts multi-value audience" test, replace with:

```ts
		expect(result).toMatchObject({ status: 200 });
```

- [ ] **Step 2: Append new tests for happy path + policy + act**

Append to `packages/oauth-token-exchange/src/__tests__/grant.test.mts`:

```ts
import { decodeJwt } from "jose";
import type { GrantPolicyContext, GrantPolicyHookBase, GrantPolicyRequest } from "@o3co/auth-provider-core";

const denyPolicy: GrantPolicyHookBase = {
	kind: "deny-all",
	async evaluate() {
		return { outcome: "deny", error: "access_denied" };
	},
};

const overridePolicy: GrantPolicyHookBase = {
	kind: "override",
	async evaluate(req: GrantPolicyRequest, _ctx: GrantPolicyContext) {
		return {
			outcome: "allow",
			grantedScope: ["read"],
			grantedAudience: ["billing"],
		};
	},
};

describe("createTokenExchangeGrant — happy path", () => {
	it("mints an access_token with issued_token_type set (minimal impersonation)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.access_token).toBeDefined();
		expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(result.tokens.refresh_token).toBeFalsy();
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.sub).toBe("user-1");
		expect(payload.family_id).toBe("fam-1");
		expect(payload.act).toBeUndefined();
	});

	it("inherits subject scope when scope parameter is omitted", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});

	it("narrows scope to requested subset", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
	});

	it("adds act claim when actor_token is provided (delegation)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-a" });
	});

	it("nests subject.act inside new act for multi-step delegation", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			act: { sub: "svc-upstream" },
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-b", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-b", act: { sub: "svc-upstream" } });
	});

	it("inherits family_id from subject (cascade revoke)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-xyz" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.family_id).toBe("fam-xyz");
	});
});

describe("createTokenExchangeGrant — policy hook", () => {
	it("rejects with access_denied when policy hook denies", async () => {
		const g = createTokenExchangeGrant({
			config: mockConfig,
			keyStore,
			refreshTokenStore: makeRefreshStore(),
			grantPolicy: denyPolicy,
			validatorRegistry: (() => {
				const r = new ExchangeTokenValidatorRegistry();
				r.register(
					ACCESS_TOKEN_TYPE,
					createSelfIssuedAccessTokenValidator({
						keyStore,
						refreshTokenStore: makeRefreshStore(),
						issuer: ISSUER,
					}),
				);
				return r;
			})(),
			clientRepository: mockClientRepository(),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 403, error: "access_denied" });
	});

	it("applies policy hook grantedScope / grantedAudience overrides", async () => {
		const g = createTokenExchangeGrant({
			config: mockConfig,
			keyStore,
			refreshTokenStore: makeRefreshStore(),
			grantPolicy: overridePolicy,
			validatorRegistry: (() => {
				const r = new ExchangeTokenValidatorRegistry();
				r.register(
					ACCESS_TOKEN_TYPE,
					createSelfIssuedAccessTokenValidator({
						keyStore,
						refreshTokenStore: makeRefreshStore(),
						issuer: ISSUER,
					}),
				);
				return r;
			})(),
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
				audience: ["billing", "inventory"],
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});
});
```

- [ ] **Step 3: Run tests to verify new tests fail**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: all new happy-path and policy tests FAIL (stub still returns 501).

- [ ] **Step 4: Finalize grant handler — replace the 501 stub with full minting**

Edit `packages/oauth-token-exchange/src/grant.mts`. At the top of the file, expand the imports:

```ts
import type {
	ClientRepository,
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyRequest,
} from "@o3co/auth-provider-core";
import { formatObject, generateToken, generateTokenResponse } from "@o3co/auth-provider-core";
import { buildActClaim } from "./act.mjs";
import type { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";
import type { ValidatedToken } from "./validator/types.mjs";
```

Then replace the final 501 stub block with:

```ts
			// Policy hook — existing GrantPolicyHookBase contract.
			let grantedScope: readonly string[] | undefined = requestedScope ?? subjectScope;
			let grantedAudience: readonly string[] | undefined = requestedAudience ?? undefined;
			if (deps.grantPolicy) {
				const policyRequest: GrantPolicyRequest = {
					grantType: GRANT_TYPE,
					clientId: client.clientId,
					subject: subjectValidated.sub,
					requestedScope: requestedScope ?? undefined,
					requestedAudience: requestedAudience ?? undefined,
					originalScope: subjectScope.length > 0 ? subjectScope : undefined,
					subjectTokenType,
					actorTokenType: actorTokenType ?? undefined,
					resource: requestedResource ?? undefined,
				};
				const policyContext: GrantPolicyContext = {
					ip: ctx.ip,
					userAgent: ctx.userAgent,
					issuer: ctx.issuer ?? "",
				};
				let decision: GrantPolicyDecision;
				try {
					decision = await deps.grantPolicy.evaluate(policyRequest, policyContext);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "grant policy evaluation failed",
						},
					};
				}
				if (decision.outcome === "deny") {
					return {
						result: {
							status: decision.error === "access_denied" ? 403 : 400,
							error: decision.error,
							errorDescription: decision.errorDescription ?? "denied by policy",
						},
					};
				}
				if (decision.grantedScope) grantedScope = decision.grantedScope;
				if (decision.grantedAudience) grantedAudience = decision.grantedAudience;
			}

			// Audience derivation (spec §8.1 rule 2):
			//   explicit narrowed audience  → use grantedAudience (already allowlist-validated)
			//   omitted + subject single    → inherit subject.aud
			//   omitted + subject multi/none → fall back to clientId (safe default)
			const subjectAud = subjectValidated.aud;
			const audienceForToken: string = (() => {
				if (grantedAudience && grantedAudience.length > 0) return grantedAudience[0]!;
				if (typeof subjectAud === "string") return subjectAud;
				return client.clientId;
			})();

			const act = buildActClaim({ subject: subjectValidated, actor: actorValidated ?? undefined });
			const scopeClaim =
				grantedScope && grantedScope.length > 0 ? grantedScope.join(" ") : null;

			const expiresIn = getExpiresIn(deps);

			const accessToken = await generateToken(
				formatObject({
					family_id: subjectValidated.familyId,
					act,
				}),
				{
					expiresIn,
					keyStore: deps.keyStore,
					issuer: ctx.issuer,
					audience: audienceForToken,
					subject: subjectValidated.sub,
					authorizedParty: client.clientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);

			const tokens = generateTokenResponse({ accessToken });
			const tokensWithIssuedType: typeof tokens & { issued_token_type: string } = {
				...tokens,
				issued_token_type: ACCESS_TOKEN_TYPE,
			};

			return {
				result: {
					status: 200,
					tokens: tokensWithIssuedType,
				},
			};
```

Finally, add the `getExpiresIn` helper at the bottom of the file (next to `normalizeArrayParam`):

```ts
function getExpiresIn(deps: TokenExchangeDependencies): number {
	const grants = (deps.config.oauth.grants ?? {}) as Record<string, Record<string, unknown>>;
	const tokenExchange = grants.token_exchange;
	const at = tokenExchange?.accessToken as { expiresIn?: number } | undefined;
	if (typeof at?.expiresIn === "number" && at.expiresIn > 0) return at.expiresIn;
	const top = (deps.config.oauth.accessToken as { expiresIn?: number } | undefined)?.expiresIn;
	return typeof top === "number" && top > 0 ? top : 300;
}
```

Note: `generateTokenResponse` currently does not include `issued_token_type`. We augment the response object with it directly in the handler to avoid a core change. The `TokenResponse` interface in core may need extending in a follow-up; for now we return the augmented object via `as`.

- [ ] **Step 5: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- grant`

Expected: every test from Tasks 6/7/8 PASSES.

- [ ] **Step 6: Verify typecheck**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0. If the `tokensWithIssuedType` cast produces a diagnostic about unknown property, the simplest fix is to widen the inline return type to `TokenResponse & { issued_token_type: string }`.

- [ ] **Step 7: Commit**

```bash
git add packages/oauth-token-exchange/src/grant.mts packages/oauth-token-exchange/src/__tests__/grant.test.mts
git commit -m "feat(token-exchange): mint access_token with issued_token_type, act claim, family cascade, policy hook"
```

---

## Task 9: GrantModule export + public API

**Files:**
- Create: `packages/oauth-token-exchange/src/module.mts`
- Modify: `packages/oauth-token-exchange/src/index.mts`
- Test: (covered by grant tests; no new unit test file)

- [ ] **Step 1: Create module.mts**

Write `packages/oauth-token-exchange/src/module.mts`:

```ts
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

import type { GrantModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "./grant.mjs";

/**
 * Config shape consumed by the Token Exchange GrantModule. All fields are
 * optional. `enabled: false` disables registration via GrantRegistry.addModule.
 */
export const tokenExchangeConfigSchema = z.object({
	token_exchange: z
		.object({
			enabled: z.boolean().default(true),
			accessToken: z
				.object({
					expiresIn: z.number().int().positive().optional(),
				})
				.optional(),
		})
		.default({}),
});

/**
 * GrantModule for plugin-style registration via
 * `GrantRegistry.addModule(tokenExchangeModule, deps)`. Consumers MUST supply
 * `validatorRegistry` and `clientRepository` in the deps, and pre-register at
 * least the self-issued access_token validator.
 */
export const tokenExchangeModule: GrantModule = {
	grants: {
		[TOKEN_EXCHANGE_GRANT_TYPE]: (deps) =>
			createTokenExchangeGrant(
				deps as unknown as Parameters<typeof createTokenExchangeGrant>[0],
			),
	},
	configSchema: tokenExchangeConfigSchema,
};
```

- [ ] **Step 2: Update index.mts — export module + grant + types**

Replace `packages/oauth-token-exchange/src/index.mts` with:

```ts
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

export {
	ACCESS_TOKEN_TYPE,
	createTokenExchangeGrant,
	type TokenExchangeDependencies,
	TOKEN_EXCHANGE_GRANT_TYPE,
} from "./grant.mjs";
export { tokenExchangeModule, tokenExchangeConfigSchema } from "./module.mjs";
export type {
	ExchangeTokenValidationContext,
	ExchangeTokenValidator,
	ValidatedToken,
} from "./validator/types.mjs";
export { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";
export {
	type CreateSelfIssuedAccessTokenValidatorOptions,
	createSelfIssuedAccessTokenValidator,
} from "./validator/selfIssuedAccessToken.mjs";
```

- [ ] **Step 3: Verify typecheck + test**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange typecheck`

Expected: exits 0.

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test`

Expected: all tests PASS.

- [ ] **Step 4: Build to confirm package compiles**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange build`

Expected: `dist/` populated with `.mjs` / `.d.mts` for each source module.

- [ ] **Step 5: Commit**

```bash
git add packages/oauth-token-exchange/src/module.mts packages/oauth-token-exchange/src/index.mts
git commit -m "feat(token-exchange): add GrantModule export + finalize public API surface"
```

---

## Task 10: Integration test with real oauth module

**Files:**
- Create: `packages/oauth-token-exchange/src/__tests__/grant-integration.test.mts`

This confirms the grant plugs into the real `/oauth/token` pipeline and family revocation cascades work end-to-end.

- [ ] **Step 1: Add integration test**

Write `packages/oauth-token-exchange/src/__tests__/grant-integration.test.mts`:

```ts
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

import type {
	ClientRepository,
	GrantContext,
	PublicClient,
	RefreshTokenStoreBase,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const client: PublicClient = {
	clientId: "client-a",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing"],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id) => (id === client.clientId ? client : null),
};

// In-memory refresh token store preserving family revocation state between
// calls, so we can revoke then re-exchange and observe the cascade.
function makeStatefulStore(): RefreshTokenStoreBase & { revokedFamilies: Set<string> } {
	const revoked = new Set<string>();
	return {
		kind: "stateful-fixture",
		revokedFamilies: revoked,
		async rotate() {
			return { outcome: "rotated" };
		},
		async isFamilyRevoked(familyId) {
			return revoked.has(familyId);
		},
		async revokeFamily(familyId) {
			revoked.add(familyId);
		},
	};
}

function buildHandler(store: RefreshTokenStoreBase) {
	const registry = new ExchangeTokenValidatorRegistry();
	registry.register(
		ACCESS_TOKEN_TYPE,
		createSelfIssuedAccessTokenValidator({
			keyStore,
			refreshTokenStore: store,
			issuer: ISSUER,
		}),
	);
	return createTokenExchangeGrant({
		config: {
			oauth: {
				jwt: { issuer: ISSUER },
				accessToken: { expiresIn: 300 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
			// biome-ignore lint/suspicious/noExplicitAny: test scaffold config
		} as any,
		keyStore,
		refreshTokenStore: store,
		validatorRegistry: registry,
		clientRepository,
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
});

describe("token_exchange — integration", () => {
	it("exchanges a subject access_token for a narrower audience access_token", async () => {
		const store = makeStatefulStore();
		const handler = buildHandler(store);
		const subjectToken = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			scope: "read write",
		});

		const { result } = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
				scope: "read",
			}),
		);

		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
		expect(payload.scope).toBe("read");
		expect(payload.family_id).toBe("fam-1");
		expect(payload.sub).toBe("user-1");
	});

	it("rejects exchange after the subject family is revoked (cascade)", async () => {
		const store = makeStatefulStore();
		const handler = buildHandler(store);
		const subjectToken = await signSelfIssuedAccessToken({ family_id: "fam-cascade" });

		// First exchange succeeds.
		const ok = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(ok.result.status).toBe(200);

		// Revoke the family (simulating a logout).
		await store.revokeFamily("fam-cascade");

		// Second exchange with the same subject must now fail.
		const denied = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(denied.result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "family_revoked",
		});
	});

	it("registers successfully via GrantRegistry.addModule", async () => {
		// Guard against drift between the GrantModule wiring and the grant handler.
		const { GrantRegistry } = await import("@o3co/auth-provider-core");
		const { tokenExchangeModule } = await import("#/module.mjs");
		const store = makeStatefulStore();
		const registry = new ExchangeTokenValidatorRegistry();
		registry.register(
			ACCESS_TOKEN_TYPE,
			createSelfIssuedAccessTokenValidator({
				keyStore,
				refreshTokenStore: store,
				issuer: ISSUER,
			}),
		);

		const grantRegistry = new GrantRegistry();
		grantRegistry.addModule(tokenExchangeModule, {
			config: {
				oauth: {
					jwt: { issuer: ISSUER },
					accessToken: { expiresIn: 300 },
					refreshToken: { expiresIn: 86400 },
					grants: {},
				},
				// biome-ignore lint/suspicious/noExplicitAny: test scaffold
			} as any,
			keyStore,
			refreshTokenStore: store,
			// biome-ignore lint/suspicious/noExplicitAny: extra deps for this grant
			validatorRegistry: registry,
			clientRepository,
		} as any);

		const handler = grantRegistry.get(TOKEN_EXCHANGE_GRANT_TYPE);
		expect(handler).toBeDefined();
	});
});
```

- [ ] **Step 2: Run tests to verify GREEN**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test -- integration`

Expected: all 3 integration tests PASS.

- [ ] **Step 3: Run the full test suite for the package**

Run: `pnpm --filter @o3co/auth-provider-oauth-token-exchange test`

Expected: every unit + integration test PASSES.

- [ ] **Step 4: Run the full repo test suite to catch regressions**

Run: `pnpm test`

Expected: every package's test suite PASSES.

- [ ] **Step 5: Commit**

```bash
git add packages/oauth-token-exchange/src/__tests__/grant-integration.test.mts
git commit -m "test(token-exchange): integration tests for narrowing + family cascade + module registration"
```

---

## Task 11: README + security notes

**Files:**
- Modify: `packages/oauth-token-exchange/README.md`

- [ ] **Step 1: Replace the placeholder README with full usage documentation**

Write `packages/oauth-token-exchange/README.md`:

````markdown
# @o3co/auth-provider-oauth-token-exchange

RFC 8693 Token Exchange grant for [auth.provider](https://github.com/o3co/auth.provider).
Supports on-behalf-of, delegation (`act` claim), and scope / audience narrowing.

## Install

```bash
pnpm add @o3co/auth-provider-oauth-token-exchange
```

## Register the grant

```ts
import { GrantRegistry } from "@o3co/auth-provider-core";
import {
  ExchangeTokenValidatorRegistry,
  createSelfIssuedAccessTokenValidator,
  tokenExchangeModule,
} from "@o3co/auth-provider-oauth-token-exchange";

const validatorRegistry = new ExchangeTokenValidatorRegistry();
validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:access_token",
  createSelfIssuedAccessTokenValidator({
    keyStore,            // your KeyStore (used to issue access_tokens)
    refreshTokenStore,   // REQUIRED for cascading revoke; fail-closed if absent
    issuer,              // your OIDC issuer URL
  }),
);

grantRegistry.addModule(tokenExchangeModule, {
  ...deps,
  validatorRegistry,
  clientRepository,
});
```

The grant type URI is `urn:ietf:params:oauth:grant-type:token-exchange` (IETF registered).

## Client configuration

Add `allowedAudiences` to the client record to permit audience narrowing to
specific API identifiers:

```yaml
clients:
  billing-gateway:
    clientSecret: "..."
    allowedScopes: ["read", "write"]
    allowedAudiences: ["billing-service", "inventory-service"]
```

When `allowedAudiences` is empty or omitted, the only accepted `audience`
parameter value is the client's own `clientId`. The audience allowlist is
enforced in addition to any `GrantPolicyHook` you register.

## External JWT subject_token

The package ships a built-in validator only for the `access_token` token type
(tokens issued by this same auth.provider instance). To accept external JWTs
as `subject_token`, implement `ExchangeTokenValidator` yourself and register
it for `urn:ietf:params:oauth:token-type:jwt`:

```ts
class ExternalJwtValidator implements ExchangeTokenValidator {
  readonly tokenType = "urn:ietf:params:oauth:token-type:jwt";
  async validate(token: string, ctx: { role: "subject" | "actor" }) {
    // Fetch jwks, verify signature, check issuer allowlist, consult remote
    // introspection for revocation — all are YOUR responsibility.
  }
}

validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:jwt",
  new ExternalJwtValidator({ ... }),
);
```

## Security notes

1. **refreshTokenStore is required.** Without it, self-issued access_tokens
   carrying `family_id` cannot be revocation-checked; the grant handler returns
   `invalid_grant` in that case (fail-closed). Token Exchange horizontally
   spreads access, so emitting tokens whose revocation cannot be observed is
   never acceptable.

2. **Scope is always narrowed.** `requested scope ⊆ subject_token.scope` is
   enforced in the core handler and cannot be bypassed by a policy hook.

3. **Audience allowlist.** The `audience` request parameter must be in
   `client.allowedAudiences ∪ { client.clientId }`. Policy hooks may further
   narrow the granted audience but cannot broaden it beyond the allowlist.

4. **Impersonation vs delegation.** An exchange without `actor_token` issues
   an impersonation token (no `act` claim). Deployments that require audit
   trails should add a `GrantPolicyHook` that rejects requests lacking
   `actor_token`:

   ```ts
   async evaluate(req) {
     if (req.grantType === "urn:ietf:params:oauth:grant-type:token-exchange" && !req.actorTokenType) {
       return { outcome: "deny", error: "invalid_request",
                errorDescription: "actor_token required for delegation" };
     }
     return { outcome: "allow" };
   }
   ```

5. **Family cascade.** Issued access_tokens inherit the subject's `family_id`
   claim. Revoking the subject's family (e.g. on logout) automatically invalidates
   every token exchanged from it.

6. **Refresh / ID tokens are never issued.** Per RFC 8693 §4.2.2 the handler
   only returns an access_token. The response always carries `issued_token_type`.

## RFC references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators (`invalid_target`)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection
````

- [ ] **Step 2: Commit**

```bash
git add packages/oauth-token-exchange/README.md
git commit -m "docs(token-exchange): add README with usage + security notes"
```

---

## Task 12: Final verification

**Files:** (no new files; full-repo checks)

- [ ] **Step 1: Full repo typecheck**

Run: `pnpm -r run typecheck`

Expected: every package exits 0. If a package without a `typecheck` script is skipped, that's fine (`--if-present` is the default behavior for `-r run`).

- [ ] **Step 2: Full repo test suite**

Run: `pnpm test`

Expected: every package's tests PASS.

- [ ] **Step 3: Full repo build**

Run: `pnpm build`

Expected: every package's `dist/` is populated; no compile errors.

- [ ] **Step 4: Lint check**

Run: `pnpm lint`

Expected: passes with 0 errors. Address any new warnings introduced by this branch (usually import order or unused imports).

- [ ] **Step 5: Verify no accidental file inclusions**

Run: `git status`

Expected: clean working tree (no untracked files, no unstaged changes).

- [ ] **Step 6: Review the branch summary**

Run: `git log --oneline main..HEAD`

Expected: a clean sequence of feat / test / docs commits, one per task, easy to bisect.
