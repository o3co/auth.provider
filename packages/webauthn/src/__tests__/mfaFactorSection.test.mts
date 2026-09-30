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
 * The WebAuthn second factor's section, `webauthn-mfa-factor` (the MFA ADR's
 * D19 `mfa.factors.webauthn`, in the configuration's own shape), which its
 * module reads: its switch and the user verification its ceremonies ask for,
 * each read from the string its variable carries, and an unknown key refused
 * by its name. Its defaults — off, `preferred` — are the package's
 * reference.conf's alone; the schema is not on the package's entry.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import * as entry from "#/index.mjs";
import { webauthnMfaFactorConfigSchema } from "#/mfaFactor/config.mjs";
import { webauthnMfaFactorConfigForTests } from "#/testing/index.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

describe("webauthn-mfa-factor, the WebAuthn second factor's section", () => {
	it("accepts the MFA ADR's defaults: off, and user verification preferred", () => {
		expect(
			webauthnMfaFactorConfigSchema.parse({ enabled: false, userVerification: "preferred" }),
		).toEqual({ enabled: false, userVerification: "preferred" });
	});

	it("reads each key from the string a variable carries", () => {
		expect(
			webauthnMfaFactorConfigSchema.parse({ enabled: "true", userVerification: "required" }),
		).toEqual({ enabled: true, userVerification: "required" });
	});

	it("refuses a key it does not know, and a user verification WebAuthn does not define", () => {
		expect(
			webauthnMfaFactorConfigSchema
				.safeParse({ enabled: false, userVerification: "preferred", residentKey: "discouraged" })
				.error?.issues.map((issue) => issue.message),
		).toEqual(["has a key it does not know: residentKey"]);
		expect(
			webauthnMfaFactorConfigSchema.safeParse({ enabled: false, userVerification: "always" })
				.success,
		).toBe(false);
	});

	it("defaults in the package's reference.conf to off, and user verification preferred", () => {
		const section = (parseFile(REFERENCE, { env: {} }).toObject() as Record<string, unknown>)[
			"webauthn-mfa-factor"
		];
		expect(webauthnMfaFactorConfigSchema.parse(section)).toEqual({
			enabled: false,
			userVerification: "preferred",
		});
	});

	it("reads each key from the variable its path names", () => {
		const section = (
			parseFile(REFERENCE, {
				env: {
					WEBAUTHN_MFA_FACTOR_ENABLED: "true",
					WEBAUTHN_MFA_FACTOR_USER_VERIFICATION: "required",
				},
			}).toObject() as Record<string, unknown>
		)["webauthn-mfa-factor"];
		expect(webauthnMfaFactorConfigSchema.parse(section)).toEqual({
			enabled: true,
			userVerification: "required",
		});
	});

	it("is built for a test by the package's testing entry, as reference.conf resolves it, with what the test lays over it", () => {
		expect(webauthnMfaFactorConfigForTests()).toEqual({
			"webauthn-mfa-factor": { enabled: false, userVerification: "preferred" },
		});
		expect(
			webauthnMfaFactorConfigForTests({ enabled: true, userVerification: "required" }),
		).toEqual({ "webauthn-mfa-factor": { enabled: true, userVerification: "required" } });
	});

	it("keeps its schema off the package's entry", () => {
		expect(Object.keys(entry)).not.toContain("webauthnMfaFactorConfigSchema");
	});
});
