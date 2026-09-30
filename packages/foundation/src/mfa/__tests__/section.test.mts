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
 * The section of the module that keeps a subject's MFA factors in the Store,
 * `foundation-mfa-factor-store`: the Store's four factor endpoints, each
 * https or loopback http, refused at config validation for an unknown key or
 * a URL of the wrong shape, naming the key and quoting what it holds in
 * printable characters alone. A composition that installs a module reading
 * the section — one that provides its store eagerly and reads the URLs first
 * — refuses the boot with any URL missing, naming each missing key and its
 * variable, whether or not anything requires the store. Here a fixture module
 * reads the section so, providing a memory store.
 */

import { BootError, createApp, type MfaFactorStore } from "@o3co/auth-provider-core";
import { makeValidAppConfig, unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
	FOUNDATION_MFA_FACTOR_STORE_SECTION,
	foundationMfaFactorStoreSection,
	readFoundationMfaFactorStoreUrls,
} from "#/mfa/section.mjs";
import { consumer, fixtureModule } from "./fixtureModule.mjs";

const URLS = {
	listUrl: "https://store.example/mfa/factors/list",
	createUrl: "https://store.example/mfa/factors/create",
	updateUrl: "https://store.example/mfa/factors/update",
	deleteUrl: "https://store.example/mfa/factors/delete",
} as const;

/** Each key, and the variable its path binds. */
const VARIABLES = {
	listUrl: "FOUNDATION_MFA_FACTOR_STORE_LIST_URL",
	createUrl: "FOUNDATION_MFA_FACTOR_STORE_CREATE_URL",
	updateUrl: "FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL",
	deleteUrl: "FOUNDATION_MFA_FACTOR_STORE_DELETE_URL",
} as const;

const KEYS = Object.keys(URLS) as (keyof typeof URLS)[];

const base = makeValidAppConfig();
const configWith = (section: unknown) => ({
	...base,
	...(section === undefined ? {} : { [FOUNDATION_MFA_FACTOR_STORE_SECTION]: section }),
});

let disposable: { dispose(): Promise<void> } | undefined;
afterEach(async () => {
	await disposable?.dispose();
	disposable = undefined;
});

async function boot(section: unknown, options: { readonly alone?: boolean } = {}) {
	const seen: { store?: MfaFactorStore } = {};
	disposable = await createApp({
		modules: options.alone === true ? [fixtureModule] : [fixtureModule, consumer(seen)],
		bootstrapComponents: { config: configWith(section), pathResolver: (p: string) => p } as never,
	});
	return seen;
}

async function bootRefusal(
	section: unknown,
	options: { readonly alone?: boolean } = {},
): Promise<BootError> {
	try {
		await boot(section, options);
	} catch (error) {
		expect(error).toBeInstanceOf(BootError);
		return error as BootError;
	}
	throw new Error("expected the boot to be refused");
}

const parse = (value: unknown) => foundationMfaFactorStoreSection.schema.safeParse(value);

describe("the section's schema", () => {
	it("is the module's own, named after it, with the package's reference.conf", () => {
		expect(FOUNDATION_MFA_FACTOR_STORE_SECTION).toBe("foundation-mfa-factor-store");
		expect(foundationMfaFactorStoreSection.reference.href).toMatch(
			/\/packages\/foundation\/config\/reference\.conf$/,
		);
		expect(unreadableModuleLeaves([fixtureModule])).toEqual([]);
	});

	it("reads the four URLs, https or http to a loopback host", () => {
		expect(parse(URLS)).toMatchObject({ success: true, data: URLS });
		const loopback = { ...URLS, listUrl: "http://127.0.0.1:8080/mfa/list" };
		expect(parse(loopback)).toMatchObject({ success: true, data: loopback });
	});

	it("reads a section with URLs left out, each absent: the module refuses them, not the schema", () => {
		const parsed = parse({});
		expect(parsed.success).toBe(true);
		for (const key of KEYS) expect(parsed.data?.[key], key).toBeUndefined();
		expect(Object.keys(parsed.data ?? {})).toEqual([]);
	});

	it("refuses a key it does not know", () => {
		const parsed = parse({ ...URLS, listURL: URLS.listUrl });
		expect(parsed.success).toBe(false);
		expect(JSON.stringify(parsed.error?.issues)).toContain("listURL");
	});

	it("names a key it does not know in printable characters alone", () => {
		const key = `list${String.fromCodePoint(0x1b)}[31m${String.fromCodePoint(0x202e)}Url\r\nforged`;
		const parsed = parse({ ...URLS, [key]: URLS.listUrl });
		const message = parsed.error?.issues[0]?.message ?? "";
		expect(message).toContain("list?[31m?Url??forged");
		expect(message).toMatch(/^[\x20-\x7e]+$/);
	});

	it("refuses a URL that is not https, or http to a loopback host, naming the key and quoting no value", () => {
		for (const [what, value] of [
			["http to another host", "http://store.internal/mfa/update"],
			["credentials in the URL", "https://user:SECRET@store.example/mfa/update"],
			["a blank variable", ""],
			["a bare host", "store.example/mfa/update"],
			["another scheme", "ftp://store.example/mfa/update"],
			["no string", 42],
		] as const) {
			const parsed = parse({ ...URLS, updateUrl: value });
			expect(parsed.success, what).toBe(false);
			expect(
				parsed.error?.issues.map((issue) => issue.path),
				what,
			).toEqual([["updateUrl"]]);
			expect(JSON.stringify(parsed.error?.issues), what).not.toContain("SECRET");
		}
	});

	it("refuses a missing section, naming the reference to layer", () => {
		const parsed = parse(undefined);
		expect(parsed.success).toBe(false);
		expect(parsed.error?.issues[0]?.message).toContain(
			"@o3co/auth-provider-foundation/reference.conf",
		);
	});
});

describe("readFoundationMfaFactorStoreUrls", () => {
	it("answers the four URLs", () => {
		expect(readFoundationMfaFactorStoreUrls(URLS)).toStrictEqual(URLS);
	});

	it("refuses, with a RangeError, a section missing any URL, naming each missing key and its variable", () => {
		for (const missing of KEYS) {
			const { [missing]: _left, ...rest } = URLS;
			expect(() => readFoundationMfaFactorStoreUrls(rest)).toThrow(RangeError);
			expect(() => readFoundationMfaFactorStoreUrls(rest)).toThrow(
				`${FOUNDATION_MFA_FACTOR_STORE_SECTION}.${missing}`,
			);
			expect(() => readFoundationMfaFactorStoreUrls(rest)).toThrow(VARIABLES[missing]);
		}
		let refusal: unknown;
		try {
			readFoundationMfaFactorStoreUrls({});
		} catch (error) {
			refusal = error;
		}
		for (const key of KEYS) {
			expect((refusal as Error).message).toContain(`${FOUNDATION_MFA_FACTOR_STORE_SECTION}.${key}`);
			expect((refusal as Error).message).toContain(VARIABLES[key]);
		}
	});
});

describe("a composition that selects the Store for MFA factors", () => {
	it("boots with the four URLs set", async () => {
		const seen = await boot(URLS);
		expect(seen.store).toBeDefined();
		await disposable?.dispose();
		disposable = undefined;
		await boot(URLS, { alone: true });
	});

	it("refuses the boot with the module installed alone, nothing requiring its store, and the URLs missing", async () => {
		const refused = await bootRefusal({}, { alone: true });
		expect(refused.reason).toBe("provides-factory-failed");
		for (const key of KEYS) {
			expect(refused.message).toContain(`${FOUNDATION_MFA_FACTOR_STORE_SECTION}.${key}`);
			expect(refused.message).toContain(VARIABLES[key]);
		}
	});

	it("refuses the boot with any URL missing, naming the key and its variable", async () => {
		for (const missing of KEYS) {
			const { [missing]: _left, ...rest } = URLS;
			const refused = await bootRefusal(rest);
			expect(refused.reason, missing).toBe("provides-factory-failed");
			expect(refused.message).toContain(`${FOUNDATION_MFA_FACTOR_STORE_SECTION}.${missing}`);
			expect(refused.message).toContain(VARIABLES[missing]);
		}
	});

	it("refuses the boot at config validation for a URL of the wrong shape or an unknown key, naming the key", async () => {
		const malformed = await bootRefusal({ ...URLS, deleteUrl: "http://store.internal/delete" });
		expect(malformed.reason).toBe("config-validation-failed");
		expect(malformed.message).toContain(`${FOUNDATION_MFA_FACTOR_STORE_SECTION}.deleteUrl`);
		const unknown = await bootRefusal({ ...URLS, markMfaEnrolledUrl: URLS.listUrl });
		expect(unknown.reason).toBe("config-validation-failed");
		expect(unknown.message).toContain("markMfaEnrolledUrl");
	});

	it("refuses the boot without the package's reference.conf layered, naming it", async () => {
		const refused = await bootRefusal(undefined);
		expect(refused.reason).toBe("config-validation-failed");
		expect(refused.message).toContain("@o3co/auth-provider-foundation/reference.conf");
	});
});
