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
 * The composition root's own section, `adapters`: which adapter fills each
 * slot. Phase one reads it alone, with the template's own strict schema, over
 * the template's own layers and its `reference.conf`, before it chooses its
 * modules; boot is not handed it. A path a selection moved from, or a
 * variable renamed with it, refuses before any module is chosen, naming the
 * new path and variable; an old variable beside its new name at the same
 * value is accepted.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "#/configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** The directories the operator layers are written to, removed after the suite. */
const operatorDirs: string[] = [];
afterAll(() => {
	for (const dir of operatorDirs) rmSync(dir, { recursive: true, force: true });
});

/** The template's own files for the production environment, under an operator's layer when given. */
function ownFiles(hocon?: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	if (hocon === undefined) return [envConfPath, applicationConfPath];
	const dir = mkdtempSync(join(tmpdir(), "adapters-"));
	operatorDirs.push(dir);
	const file = join(dir, "operator.conf");
	writeFileSync(file, hocon);
	return [file, envConfPath, applicationConfPath];
}

/** Phase one's reading of `adapters`, under `env` and an operator's `hocon`. */
const adaptersFrom = (env: Record<string, string> = {}, hocon?: string) =>
	readSwitches(readOwnLayers(ownFiles(hocon), { env })).adapters;

/** What phase one refuses under `env` and an operator's `hocon`. */
function refusal(env: Record<string, string> = {}, hocon?: string): Error {
	try {
		adaptersFrom(env, hocon);
	} catch (err) {
		return err as Error;
	}
	throw new Error("phase one read the adapters");
}

/** Each selection: its key, the variable that sets it, the path and variable it moved from, a value it takes. */
const SELECTIONS = [
	["rateLimiter", "RATE_LIMITER", "rateLimiter.adapter", "RATE_LIMITER_ADAPTER", "redis"],
	[
		"userSessionStores",
		"USER_SESSION_STORES",
		"userSessionStores.adapter",
		"USER_SESSION_STORES_ADAPTER",
		"redis",
	],
	[
		"accessTokenDenylist",
		"ACCESS_TOKEN_DENYLIST",
		"accessTokenDenylist.adapter",
		"ACCESS_TOKEN_DENYLIST_ADAPTER",
		"memory",
	],
	["replaySeenSet", "REPLAY_SEEN_SET", "replaySeenSet.adapter", "REPLAY_SEEN_SET_ADAPTER", "memory"],
	["consentStore", "CONSENT_STORE", "consentStore.adapter", "CONSENT_STORE_ADAPTER", "memory"],
	[
		"federationTokenStore",
		"FEDERATION_TOKEN_STORE",
		"federationTokenStore.type",
		"FEDERATION_TOKEN_STORE_TYPE",
		"redis",
	],
	[
		"federationGrantStore",
		"FEDERATION_GRANT_STORE",
		"federationGrantStore.adapter",
		"FEDERATION_GRANT_STORE_ADAPTER",
		"memory",
	],
	[
		"federationGrantIntentStore",
		"FEDERATION_GRANT_INTENT_STORE",
		"federationGrantIntentStore.adapter",
		"FEDERATION_GRANT_INTENT_STORE_ADAPTER",
		"memory",
	],
	[
		"mfaFactorStore",
		"MFA_FACTOR_STORE",
		"mfaFactorStore.adapter",
		"MFA_FACTOR_STORE_ADAPTER",
		"store",
	],
	[
		"mfaTransactionStore",
		"MFA_TRANSACTION_STORE",
		"mfaTransactionStore.adapter",
		"MFA_TRANSACTION_STORE_ADAPTER",
		"redis",
	],
	["codeRepository", "CODE_REPOSITORY", "oauth.code.adapter", "OAUTH_CODE_ADAPTER", "memory"],
	["codeRepository", "CODE_REPOSITORY", "repositories.code.type", "CLIENT_CODE_TYPE", "memory"],
	["clientRepository", "CLIENT_REPOSITORY", "repositories.client.type", "CLIENT_TYPE", "yaml"],
	["userRepository", "USER_REPOSITORY", "repositories.user.type", "CLIENT_USER_TYPE", "yaml"],
	["auditSink", "AUDIT_SINK", "audit.sink.type", "AUDIT_SINK_TYPE", "console"],
] as const;

describe("the shipped selections", () => {
	it("reads every selection from the template's reference.conf, at the values the template ships", () => {
		expect(adaptersFrom()).toEqual({
			rateLimiter: "memory",
			userSessionStores: "memory",
			accessTokenDenylist: "redis",
			replaySeenSet: "redis",
			consentStore: "none",
			federationTokenStore: "memory",
			federationGrantStore: "redis",
			federationGrantIntentStore: "redis",
			mfaFactorStore: "memory",
			mfaTransactionStore: "memory",
			codeRepository: "redis",
			clientRepository: "yaml",
			userRepository: "http",
			auditSink: "logger",
		});
	});

	it.each(SELECTIONS)(
		"reads adapters.%s from ADAPTERS_%s",
		(key, name, _oldPath, _oldName, value) => {
			expect(adaptersFrom({ [`ADAPTERS_${name}`]: value })[key]).toBe(value);
		},
	);

	it("reads a selection an operator writes in HOCON", () => {
		expect(adaptersFrom({}, 'adapters.rateLimiter = "redis"\n').rateLimiter).toBe("redis");
	});

	it("refuses a value its schema does not know, naming the key", () => {
		expect(refusal({ ADAPTERS_RATE_LIMITER: "memcached" }).message).toMatch(
			/adapters\.rateLimiter/,
		);
	});

	it("refuses a key the section does not declare, naming it", () => {
		expect(refusal({}, 'adapters.sessionStore = "redis"\n').message).toMatch(/sessionStore/);
	});
});

describe("a path a selection moved from, written in the operator's own layer", () => {
	it.each(SELECTIONS)(
		"adapters.%s: refused where it was, %s's old path, naming the new path and ADAPTERS_%s",
		(key, name, oldPath, _oldName, value) => {
			const err = refusal({}, `${oldPath} = "${value}"\n`);
			expect(err).toBeInstanceOf(RangeError);
			expect(err.message).toContain(`${oldPath} has moved to adapters.${key}`);
			expect(err.message).toContain(`ADAPTERS_${name}`);
		},
	);

	it("names every old path it finds, in one refusal", () => {
		const err = refusal(
			{},
			'rateLimiter.adapter = "redis"\nconsentStore.adapter = "memory"\naudit.sink.type = "console"\n',
		);
		for (const path of ["rateLimiter.adapter", "consentStore.adapter", "audit.sink.type"]) {
			expect(err.message).toContain(path);
		}
	});
});

describe("a variable renamed with a selection", () => {
	it.each(SELECTIONS)(
		"adapters.%s: %s's old variable set alone is refused, naming ADAPTERS_%s",
		(key, name, _oldPath, oldName, value) => {
			const err = refusal({ [oldName]: value });
			expect(err).toBeInstanceOf(RangeError);
			expect(err.message).toContain(`${oldName} was renamed ADAPTERS_${name}`);
			expect(err.message).toContain(`adapters.${key}`);
		},
	);

	it.each(SELECTIONS)(
		"adapters.%s: the old variable beside ADAPTERS_%s at a different value is refused, quoting neither",
		(_key, name, _oldPath, oldName) => {
			const err = refusal({ [oldName]: "old-value-5e2d", [`ADAPTERS_${name}`]: "new-value-c81a" });
			expect(err.message).toContain(oldName);
			expect(err.message).not.toContain("old-value-5e2d");
			expect(err.message).not.toContain("new-value-c81a");
		},
	);

	it.each(SELECTIONS)(
		"adapters.%s: the old variable beside ADAPTERS_%s at the same value is read",
		(key, name, _oldPath, oldName, value) => {
			expect(adaptersFrom({ [oldName]: value, [`ADAPTERS_${name}`]: value })[key]).toBe(value);
		},
	);
});

describe("the modules phase one chooses by the selections", () => {
	const names = (env: Record<string, string>) =>
		buildModules(readSwitches(readOwnLayers(ownFiles(), { env })), {
			environment: "production",
		}).map((module) => module.name);

	it.each([
		["ADAPTERS_RATE_LIMITER", "redis", "redis-rate-limiter", "core-rate-limiter-memory"],
		["ADAPTERS_RATE_LIMITER", "memory", "core-rate-limiter-memory", "redis-rate-limiter"],
		[
			"ADAPTERS_CODE_REPOSITORY",
			"memory",
			"standalone-in-memory-code-repository",
			"redis-code-repository",
		],
		[
			"ADAPTERS_CODE_REPOSITORY",
			"redis",
			"redis-code-repository",
			"standalone-in-memory-code-repository",
		],
		[
			"ADAPTERS_USER_SESSION_STORES",
			"redis",
			"redis-session-stores",
			"standalone-in-memory-session-stores",
		],
		["ADAPTERS_CONSENT_STORE", "memory", "core-consent-store-memory", "redis-consent-store"],
	])("%s=%s installs %s, not %s", (variable, value, installed, absent) => {
		const modules = names({ [variable]: value });
		expect(modules).toContain(installed);
		expect(modules).not.toContain(absent);
	});
});

describe("boot and the section", () => {
	it("hands boot no adapters section: the composition root consumed it", () => {
		const own = readOwnLayers(ownFiles(), { env: {} });
		const switches = readSwitches(own);
		const resolved = resolveForBoot(
			own,
			buildModules(switches, { environment: "production" }),
			expectedSessionRequirements(switches),
		);
		expect(resolved).not.toHaveProperty("adapters");
	});
});
