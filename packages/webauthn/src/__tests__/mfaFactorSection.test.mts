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
 * D19 `mfa.factors.webauthn`, in #728's shape), declared as a schema before
 * its module exists: its switch and the user verification a registration
 * asks for, each read from the string its variable carries, and an unknown
 * key refused. Its defaults are not in the package's reference.conf yet: a
 * section there that no installed module owns is named ignored at every boot
 * of every composition that installs the WebAuthn grant.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import * as entry from "#/index.mjs";
import { webauthnMfaFactorConfigSchema } from "#/mfaFactor/config.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

describe("webauthn-mfa-factor, the WebAuthn second factor's section", () => {
	it("reads the MFA ADR's defaults: off, and user verification preferred", () => {
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

	it("is not in the package's reference.conf, nor on its entry, before its module exists", () => {
		expect(parseFile(REFERENCE, { env: {} }).toObject()).not.toHaveProperty("webauthn-mfa-factor");
		expect(Object.keys(entry)).not.toContain("webauthnMfaFactorConfigSchema");
	});
});
