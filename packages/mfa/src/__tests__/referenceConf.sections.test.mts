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
 * The package's `config/reference.conf`: the modules that read it
 * declare it as their section's reference, and it holds only their
 * sections, which their section schemas parse without losing a path —
 * core's `packageReferenceProblems`, the check every package with defaults
 * runs over its own file. It binds no variable at the TOTP factor's old path:
 * the two whose names changed with the move are declared on the factor's
 * manifest instead (`section.renamedVariables`), which boot holds to their
 * new names.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { mfaEmailFactorModule } from "#/email/module.mjs";
import { mfaModule } from "#/module.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The TOTP factor's old path, and its section's path now. */
const OLD_PATH = "mfa.factors.totp";
const NEW_PATH = "mfa-totp-factor";

const MARKER = "__MFA_REFERENCE_MARKER__";

/** Every path in `tree` whose value is the marker. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	if (typeof tree === "object" && tree !== null && !Array.isArray(tree)) {
		return Object.entries(tree).flatMap(([key, value]) =>
			markedPaths(value, prefix === "" ? key : `${prefix}.${key}`),
		);
	}
	return tree === MARKER ? [prefix] : [];
}

/** Each path the file binds a variable at, as `VARIABLE at path`. */
function bindings(): string[] {
	const file = fileURLToPath(REFERENCE);
	const variables = [
		...new Set(
			[...readFileSync(file, "utf8").matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) =>
				String(match[1]),
			),
		),
	];
	return variables.flatMap((variable) =>
		markedPaths(parseFile(file, { env: { [variable]: MARKER } }).toObject()).map(
			(path) => `${variable} at ${path}`,
		),
	);
}

describe("the package's config/reference.conf", () => {
	const modules = [
		mfaModule(),
		mfaTotpFactorModule,
		mfaRecoveryCodeFactorModule,
		mfaEmailFactorModule,
	];

	it("is read at each module's name: mfa, mfa-totp-factor, mfa-recovery-code-factor and mfa-email-factor", () => {
		expect(modules.map((module) => Object.hasOwn(module.section ?? {}, "at"))).toEqual([
			false,
			false,
			false,
			false,
		]);
		expect(modules.map((module) => module.name)).toEqual([
			"mfa",
			NEW_PATH,
			"mfa-recovery-code-factor",
			"mfa-email-factor",
		]);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
			parseFile(path, { env: { ...env } }).toObject();
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([]);
	});

	it("binds no variable at the TOTP factor's old path, and sets nothing there", () => {
		expect(bindings().filter((binding) => binding.includes(` at ${OLD_PATH}.`))).toEqual([]);
		expect(bindings().filter((binding) => binding.startsWith("MFA_TOTP_ENABLED "))).toEqual([
			"MFA_TOTP_ENABLED at renamed-variables.MFA_TOTP_ENABLED",
		]);
		const mfa = (parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject() as { mfa?: object })
			.mfa;
		expect(mfa).not.toHaveProperty("factors");
	});

	it("declares the variables renamed with the TOTP factor's move on its manifest, each by the old path it was bound to", () => {
		expect(mfaTotpFactorModule.section?.renamedVariables).toEqual({
			MFA_TOTP_ENABLED: "mfa.factors.totp.enabled",
			MFA_TOTP_ISSUER: "mfa.factors.totp.issuer",
		});
		expect(bindings()).toEqual(
			expect.arrayContaining([
				`MFA_TOTP_FACTOR_ENABLED at ${NEW_PATH}.enabled`,
				`MFA_TOTP_FACTOR_ISSUER at ${NEW_PATH}.issuer`,
			]),
		);
	});

	it("declares on the MFA module's manifest the page's old path, endpoints.mfa.url, and its variable, ENDPOINTS_MFA_URL, and the removed mfa.rateLimit; binds MFA_PAGE_URL at mfa.page.url and the old name in its capture alone", () => {
		const section = mfaModule().section;
		expect(section?.relocatedFrom).toEqual({
			"endpoints.mfa.url": "page.url",
			"mfa.rateLimit": null,
		});
		expect(section?.renamedVariables).toEqual({ ENDPOINTS_MFA_URL: "endpoints.mfa.url" });
		expect(bindings().filter((binding) => binding.startsWith("MFA_PAGE_URL "))).toEqual([
			"MFA_PAGE_URL at mfa.page.url",
			"MFA_PAGE_URL at renamed-variables.MFA_PAGE_URL",
		]);
		expect(bindings().filter((binding) => binding.startsWith("ENDPOINTS_MFA_URL "))).toEqual([
			"ENDPOINTS_MFA_URL at renamed-variables.ENDPOINTS_MFA_URL",
		]);
	});
});
