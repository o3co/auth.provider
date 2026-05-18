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
import type { IntrospectResponse } from "../types/introspect.mjs";

describe("IntrospectResponse typed shape", () => {
	it("active response with no cnf", () => {
		const r: IntrospectResponse = {
			active: true,
			exp: 1700000000,
			iat: 1699999000,
			iss: "https://issuer.example",
			sub: "user-1",
			scope: "read",
			token_type: "Bearer",
		};
		expect(r.active).toBe(true);
		expect(r.cnf).toBeUndefined();
	});

	it("active response with DPoP cnf returns token_type=DPoP", () => {
		const r: IntrospectResponse = {
			active: true,
			exp: 1700000000,
			iat: 1699999000,
			iss: "https://issuer.example",
			sub: "user-1",
			scope: "read",
			token_type: "DPoP",
			cnf: { jkt: "abc123" },
		};
		expect(r.cnf).toEqual({ jkt: "abc123" });
		expect(r.token_type).toBe("DPoP");
	});

	it("active response with mTLS cnf keeps token_type=Bearer", () => {
		const r: IntrospectResponse = {
			active: true,
			cnf: { "x5t#S256": "def456" },
			token_type: "Bearer",
		};
		expect(r.cnf).toEqual({ "x5t#S256": "def456" });
		expect(r.token_type).toBe("Bearer");
	});

	it("inactive response omits everything except active=false", () => {
		const r: IntrospectResponse = { active: false };
		expect(r.active).toBe(false);
		expect(r.cnf).toBeUndefined();
		expect(r.token_type).toBeUndefined();
	});
});
