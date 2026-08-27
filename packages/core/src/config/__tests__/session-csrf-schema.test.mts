/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * #272 follow-up — `session.csrf.ttlSeconds` was `z.coerce.number()`, which
 * accepts any number at all. Every value it lets through that is not a
 * positive integer breaks the token arm silently rather than loudly:
 *
 * - `0` (which is what HOCON substituting an empty env var coerces to) mints
 *   tokens that are already expired, so the double-submit arm is dead and
 *   every header-less client is locked out with no configuration visibly wrong.
 * - a decimal mints an expiry that fails the token's own shape check, so every
 *   issued token is unverifiable — including the ones the provider just handed
 *   out from `GET /session/csrf`.
 *
 * The schema is the first of two guards; the second is
 * `createCsrfProtection`'s own check, for hand-built configs that never meet
 * zod. Both are pinned — here and in `packages/session/src/__tests__/csrf.test.mts`.
 */

import { describe, expect, it } from "vitest";
import { fullSectionsSchema } from "../application.schema.mjs";

const csrfSchema = fullSectionsSchema.shape.session.shape.csrf;

/** Upper bound restated from `@o3co/auth-provider-session`'s `csrf.mts`. */
const MAX_TTL_SECONDS = 86_400;

describe("session.csrf schema — ttlSeconds bounds", () => {
	it("accepts the reference.conf default", () => {
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: 7200 }).success).toBe(true);
	});

	it("accepts the section being absent entirely", () => {
		// Every value has a code-side default, so a hand-built config is not
		// forced to restate a section it has no opinion about.
		expect(csrfSchema.safeParse(undefined).success).toBe(true);
	});

	it("rejects a decimal ttlSeconds", () => {
		// `7200.5` stringifies into the token as a decimal expiry, which the
		// token's own shape regex rejects — every minted token becomes
		// unverifiable, including the ones GET /session/csrf just issued.
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: 7200.5 }).success).toBe(false);
	});

	it("rejects a zero ttlSeconds", () => {
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: 0 }).success).toBe(false);
	});

	it("rejects a negative ttlSeconds", () => {
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: -1 }).success).toBe(false);
	});

	it("rejects the empty string HOCON substitutes for an unset env var", () => {
		// `SESSION_CSRF_TTL_SECONDS=` in a .env file, a compose `environment:`
		// entry, or a blank ConfigMap key all arrive as `""`, and
		// `z.coerce.number()` turns that into `0` — a silently dead token arm.
		// This is the same trap `http.readinessTimeoutMs` documents.
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: "" }).success).toBe(false);
	});

	it("rejects a ttlSeconds beyond the documented ceiling", () => {
		expect(
			csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: MAX_TTL_SECONDS + 1 }).success,
		).toBe(false);
	});

	it("accepts the ceiling itself", () => {
		expect(csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: MAX_TTL_SECONDS }).success).toBe(
			true,
		);
	});

	it("still coerces a numeric string, which is what HOCON hands over", () => {
		const result = csrfSchema.safeParse({ trustedOrigins: [], ttlSeconds: "3600" });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data?.ttlSeconds).toBe(3600);
	});
});
