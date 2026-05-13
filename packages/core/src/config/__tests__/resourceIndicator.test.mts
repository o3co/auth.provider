/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "../application.schema.mjs";

/**
 * Access the resourceIndicator sub-schema directly so we can test the
 * boolean-from-HOCON coercion without standing up a full AppConfig fixture.
 *
 * The field is `.optional()` in the schema — default `false` lives in
 * `packages/core/config/reference.conf` per ADR 2026-04-30.
 */
const resourceIndicatorSchema = CoreConfigSchema.shape.oauth.shape.resourceIndicator;

describe("oauth.resourceIndicator schema — Wave 1 §5.3 / RFC 8707 opt-in foundation", () => {
	it("is absent when omitted (optional field — default lives in reference.conf)", () => {
		// The full oauth block still needs its required fields; we test
		// resourceIndicator in isolation via the sub-schema.
		const result = resourceIndicatorSchema.safeParse(undefined);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toBeUndefined();
	});

	it("accepts enabled=true (boolean)", () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: true });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data?.enabled).toBe(true);
	});

	it("accepts enabled=false (boolean)", () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: false });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data?.enabled).toBe(false);
	});

	it('accepts enabled="true" (HOCON env-substitution returns string) and coerces to boolean true', () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: "true" });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data?.enabled).toBe(true);
	});

	it('accepts enabled="false" (HOCON env-substitution returns string) and coerces to boolean false', () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: "false" });
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data?.enabled).toBe(false);
	});

	it('rejects enabled="yes" (not a recognized boolean string)', () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: "yes" });
		expect(result.success).toBe(false);
	});

	it("rejects enabled=42 (non-string non-boolean)", () => {
		const result = resourceIndicatorSchema.safeParse({ enabled: 42 });
		expect(result.success).toBe(false);
	});
});
