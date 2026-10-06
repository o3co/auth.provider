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
 * Stage 1 takes one frozen plain-data copy of the configuration it is handed
 * (`copyPlainJson`) before anything reads it — every field read once, a getter
 * run once — and every check, the composed parse and the `config` slot read
 * that copy alone. A getter or a Proxy trap of a configuration built in code
 * cannot answer one thing to a check and another to a later stage, and the
 * copy holds no accessor, Proxy or foreign prototype. A read that throws, or a
 * value JSON would not give back as it is, refuses boot naming where, never
 * with what a read threw. The host's object is neither frozen nor changed. A
 * configuration resolved from HOCON, which is plain data, boots as it did.
 */

import { parseString } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError } from "#/boot/types.mjs";
import { validateManifests } from "#/boot/validate-manifests.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** Core's valid configuration, none of the oauth package's grant switches. */
const base = (): Record<string, unknown> => {
	const {
		"oauth-session": _session,
		"oauth-authorization": _authorization,
		...rest
	} = makeValidCoreConfig() as Record<string, unknown>;
	return rest;
};

const boot = (config: unknown, modules: Parameters<typeof createApp>[0]["modules"] = []) =>
	createApp({
		modules,
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});

const refusal = async (booting: Promise<{ dispose(): Promise<void> }>): Promise<BootError> => {
	const caught = await booting.then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);
	expect(caught).toBeInstanceOf(BootError);
	return caught as BootError;
};

const issuePathsOf = (err: BootError): PropertyKey[][] =>
	(err.details as unknown as { issues: { path: PropertyKey[] }[] }).issues.map((issue) => [
		...issue.path,
	]);

describe("the configuration stage 1 is handed is copied once, and only the copy is read", () => {
	it("keeps the issuer it checked when another key's getter rewrites the configuration later", async () => {
		const written = base();
		const config: Record<string, unknown> = {
			...written,
			get custom(): boolean {
				// Rewrites whatever object it is read from that is not the host's.
				if (this !== config) {
					(
						(this as { oauth: { jwt: { issuer: string } } }).oauth.jwt as { issuer: string }
					).issuer = "https://evil.test/";
				}
				return true;
			},
		};
		const handle = await boot(config);
		try {
			const slot = handle.components.config as unknown as {
				oauth: { jwt: { issuer: unknown } };
				custom: unknown;
			};
			expect(slot.oauth.jwt.issuer).toBe("https://auth.test");
			expect(slot.custom).toBe(true);
		} finally {
			await handle.dispose();
		}
	});

	it("judges the renamed-variable captures it enumerated, though a Proxy hides them from a later enumeration", async () => {
		const written = base();
		const captures = written["renamed-variables"] as Record<string, unknown>;
		let enumerations = 0;
		const config = new Proxy(
			{ ...written, "renamed-variables": { ...captures, DEPLOYMENT_MODE: "multi" } },
			{
				ownKeys(target) {
					enumerations += 1;
					const keys = Reflect.ownKeys(target);
					return enumerations === 1 ? keys : keys.filter((key) => key !== "renamed-variables");
				},
			},
		);
		const err = await refusal(boot(config));
		expect(err.reason).toBe("environment-variable-renamed");
		expect(enumerations).toBe(1);
	});

	it.each([
		["prototype", { issuer: "https://auth.test", prototype: 1 }],
		["__proto__", JSON.parse('{"issuer":"https://auth.test","__proto__":1}') as object],
	])("refuses a reserved key %j a getter answers, at its path", async (key, jwt) => {
		const config = {
			...base(),
			oauth: {
				...(base().oauth as object),
				get jwt(): object {
					return jwt;
				},
			},
		};
		const err = await refusal(boot(config));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePathsOf(err)).toEqual([["oauth", "jwt", key]]);
	});

	it.each([
		[
			"an ownKeys trap",
			{
				ownKeys(): never {
					throw new Error("SECRET https://secret.example");
				},
			},
		],
		[
			"a getPrototypeOf trap",
			{
				getPrototypeOf(): never {
					throw new Error("SECRET https://secret.example");
				},
			},
		],
	])("refuses a value whose %s throws, naming where and never what it threw", async (_, trap) => {
		const config = {
			...base(),
			oauth: {
				...(base().oauth as object),
				get jwt(): object {
					return new Proxy({ issuer: "https://auth.test" }, trap);
				},
			},
		};
		const err = await refusal(boot(config));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("the configuration at .oauth.jwt is not plain data");
		expect(err.message).not.toContain("SECRET");
	});

	it("refuses a top-level getter that throws, naming its key, before any check reads it", async () => {
		const config = {
			...base(),
			get oauth(): never {
				throw new Error("SECRET");
			},
		};
		const err = await refusal(boot(config));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("the configuration at .oauth is not plain data");
		expect(err.message).not.toContain("SECRET");
	});

	it("refuses a configuration that contains itself, at the key that does", async () => {
		const config: Record<string, unknown> = base();
		config.loop = { back: config };
		const err = await refusal(boot(config));
		expect(err.message).toContain("the configuration at .loop.back is not plain data");
	});

	it("reads a getter once: the value checked is the one the config slot holds, as a data property", async () => {
		let reads = 0;
		const jwt = {
			get issuer(): string {
				reads += 1;
				return reads === 1 ? "https://auth.test" : "https://evil.test/";
			},
		};
		const config = { ...base(), oauth: { ...(base().oauth as object), jwt } };
		const handle = await boot(config);
		try {
			const slot = handle.components.config as unknown as { oauth: { jwt: object } };
			expect(reads).toBe(1);
			expect(Object.getOwnPropertyDescriptor(slot.oauth.jwt, "issuer")).toMatchObject({
				value: "https://auth.test",
			});
			// The host's object is neither frozen nor changed.
			expect(Object.isFrozen(config)).toBe(false);
			expect(Object.getOwnPropertyDescriptor(jwt, "issuer")?.get).toBeTypeOf("function");
		} finally {
			await handle.dispose();
		}
	});

	it("holds no Proxy or foreign prototype: a Proxy over plain data is copied as its data", async () => {
		const oauth = new Proxy({ ...(base().oauth as object) }, {});
		const handle = await boot({ ...base(), oauth });
		try {
			const slot = handle.components.config as unknown as { oauth: object };
			expect(slot.oauth).not.toBe(oauth);
			expect(Object.getPrototypeOf(slot.oauth)).toBe(Object.prototype);
			expect(slot.oauth).toEqual(base().oauth);
		} finally {
			await handle.dispose();
		}
	});

	it.each([
		["a class instance", new (class Settings {})()],
		["a Date", new Date(0)],
		["a symbol's field", { [Symbol("hidden")]: 1 }],
	])("refuses %s, which configuration cannot hold, naming where", async (_, value) => {
		const err = await refusal(boot({ ...base(), widget: { value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/the configuration at \.widget(\.value)? is not plain data/);
	});

	it("boots a configuration resolved from HOCON as written, its sections in the config slot", async () => {
		const written = base();
		const resolved = {
			...(parseString(
				'core.sessionRequirements.expected = []\noauth { jwt.issuer = "https://auth.test", refreshToken.expiresIn = 86400, accessToken.defaultExpiresIn = 3600 }\nwidget { size = 3, list = [1, { a = 2 }], empty = {} }',
			).toObject() as Record<string, unknown>),
			"renamed-variables": written["renamed-variables"],
		};
		const handle = await boot(resolved);
		try {
			const { "renamed-variables": _captures, ...expected } = resolved;
			expect(handle.components.config).toEqual(expected);
			expect(Object.isFrozen(handle.components.config)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the config slot of the bootstrap map is read once, as an own property", () => {
	it("reads an own config getter once, through createApp and through validateManifests", async () => {
		let reads = 0;
		const written = base();
		const bootstrapComponents = {
			pathResolver: (p: string) => p,
			get config(): unknown {
				reads += 1;
				return written;
			},
		};
		const handle = await createApp({
			modules: [],
			bootstrapComponents: bootstrapComponents as never,
		});
		await handle.dispose();
		expect(reads).toBe(1);

		reads = 0;
		const validated = validateManifests({
			modules: [],
			bootstrapComponents: bootstrapComponents as never,
		});
		expect(reads).toBe(1);
		expect((validated.bootstrapComponents.config as { core?: unknown }).core).toEqual(written.core);
	});

	it.each([
		["createApp", (map: object) => createApp({ modules: [], bootstrapComponents: map as never })],
		[
			"validateManifests",
			async (map: object) => validateManifests({ modules: [], bootstrapComponents: map as never }),
		],
	])(
		"refuses a config slot whose read throws, through %s, never with what it threw",
		async (_, run) => {
			const map = {
				pathResolver: (p: string) => p,
				get config(): never {
					throw new Error("SECRET https://secret.example");
				},
			};
			const caught = await Promise.resolve()
				.then((): Promise<unknown> => run(map))
				.then(
					() => undefined,
					(e: unknown) => e,
				);
			expect(caught).toBeInstanceOf(BootError);
			expect((caught as BootError).reason).toBe("config-validation-failed");
			expect((caught as BootError).message).not.toContain("SECRET");
		},
	);

	it("reads no config the bootstrap map inherits: it is absent, and refused as none, unread", () => {
		let reads = 0;
		const inherited = {
			get config(): unknown {
				reads += 1;
				return base();
			},
		};
		const map = Object.assign(Object.create(inherited) as object, {
			pathResolver: (p: string) => p,
		});
		// Refused as a map handed no configuration, the inherited getter unread.
		expect(() => validateManifests({ modules: [], bootstrapComponents: map as never })).toThrow(
			/handed no configuration/,
		);
		expect(reads).toBe(0);
	});
});

describe("negative zero, which HOCON can resolve, reads as zero, as JSON writes it", () => {
	it("boots core.sessionLifecycle.sweepIntervalSeconds = -0 as 0", async () => {
		const written = base();
		const resolved = {
			...written,
			core: {
				...(written.core as object),
				...(parseString("sessionLifecycle.sweepIntervalSeconds = -0").toObject() as object),
			},
		};
		expect(
			Object.is(
				(resolved.core as { sessionLifecycle: { sweepIntervalSeconds: unknown } }).sessionLifecycle
					.sweepIntervalSeconds,
				-0,
			),
		).toBe(true);
		const handle = await boot(resolved);
		try {
			const slot = handle.components.config as unknown as {
				core: { sessionLifecycle: { sweepIntervalSeconds: unknown } };
			};
			expect(Object.is(slot.core.sessionLifecycle.sweepIntervalSeconds, 0)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});
