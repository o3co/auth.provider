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
 * The one boundary where boot reads a host map (`host-maps.mts`), called first
 * by createApp and by a direct validateManifests: its own keys listed once,
 * each slot's own property read once into a data property of a map without a
 * prototype, `config` copied as frozen plain data. A listing or a read that
 * throws refuses under the slot's own reason, never with what it threw; the
 * host's map is never changed.
 */

import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { snapshotHostMap } from "#/boot/host-maps.mjs";
import { BootError } from "#/boot/types.mjs";
import { validateManifests } from "#/boot/validate-manifests.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import type { GrantPolicyHook } from "#/policy/types.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const noopGrantPolicy: GrantPolicyHook = {
	kind: "noop",
	async evaluate() {
		return { outcome: "allow" };
	},
};

/** Core's valid configuration, without an issuer, none of the oauth package's grant switches. */
const withoutIssuer = (): Record<string, unknown> => {
	const {
		oauth,
		"oauth-session": _session,
		"oauth-authorization": _authorization,
		...rest
	} = makeValidCoreConfig() as Record<string, unknown> & { oauth: Record<string, unknown> };
	const { jwt: _jwt, ...oauthWithoutJwt } = oauth;
	return { ...rest, oauth: oauthWithoutJwt };
};

/** What `run` threw, or a failure when it did not. */
const thrown = async (run: () => unknown): Promise<BootError> => {
	const caught = await Promise.resolve()
		.then(run)
		.then(
			() => undefined,
			(e: unknown) => e,
		);
	expect(caught).toBeInstanceOf(BootError);
	return caught as BootError;
};

const viaCreateApp = (bootstrapComponents: object) => () =>
	createApp({ modules: [], bootstrapComponents: bootstrapComponents as never });
const viaValidate = (bootstrapComponents: object) => () =>
	validateManifests({ modules: [], bootstrapComponents: bootstrapComponents as never });

describe("the host-map boundary", () => {
	it("reads a component slot's getter once: the grantPolicy checked is the one handed on", async () => {
		for (const enter of ["createApp", "validateManifests"] as const) {
			let reads = 0;
			const map = {
				config: withoutIssuer(),
				pathResolver: (p: string) => p,
				get grantPolicy(): GrantPolicyHook | undefined {
					reads += 1;
					return reads <= 2 ? noopGrantPolicy : undefined;
				},
			};
			const err = await thrown(enter === "createApp" ? viaCreateApp(map) : viaValidate(map));
			expect(err.reason, enter).toBe("grant-policy-without-issuer");
			expect(reads, enter).toBe(1);
		}
	});

	it("reads configDefaults from the snapshot, never reading config through a spread first", async () => {
		let configReads = 0;
		const map = {
			pathResolver: (p: string) => p,
			configDefaults: {},
			get config(): unknown {
				configReads += 1;
				if (configReads > 1) throw new Error("SECRET second read");
				return withoutIssuer();
			},
		};
		validateManifests({ modules: [], bootstrapComponents: map as never });
		expect(configReads).toBe(1);
	});

	it.each([
		["createApp", viaCreateApp],
		["validateManifests", viaValidate],
	])(
		"refuses a configDefaults getter that throws as config-defaults-invalid, through %s, without its text",
		async (_, enter) => {
			const map = {
				config: withoutIssuer(),
				pathResolver: (p: string) => p,
				get configDefaults(): never {
					throw new Error("SECRET");
				},
			};
			const err = await thrown(enter(map));
			expect(err.reason).toBe("config-defaults-invalid");
			expect(err.message).not.toContain("SECRET");
		},
	);

	it.each([
		[
			"listing its keys",
			{
				ownKeys(): never {
					throw new Error("SECRET");
				},
			},
			"config-validation-failed",
		],
		[
			"reading the config slot's descriptor",
			{
				getOwnPropertyDescriptor(target: object, key: PropertyKey) {
					if (key === "config") throw new Error("SECRET");
					return Reflect.getOwnPropertyDescriptor(target, key);
				},
			},
			"config-validation-failed",
		],
		[
			"reading a component slot's descriptor",
			{
				getOwnPropertyDescriptor(target: object, key: PropertyKey) {
					if (key === "pathResolver") throw new Error("SECRET");
					return Reflect.getOwnPropertyDescriptor(target, key);
				},
			},
			"missing-required-component",
		],
	])("refuses a map whose %s throws, without its text", async (_, trap, reason) => {
		for (const enter of [viaCreateApp, viaValidate]) {
			const map = new Proxy({ config: withoutIssuer(), pathResolver: (p: string) => p }, trap);
			const err = await thrown(enter(map));
			expect(err.reason).toBe(reason);
			expect(err.message).not.toContain("SECRET");
		}
	});

	it("reads each slot's own descriptor once: a trap answering differently on a later query is never asked again", async () => {
		let queries = 0;
		const map = new Proxy(
			{ config: withoutIssuer(), pathResolver: (p: string) => p },
			{
				getOwnPropertyDescriptor(target, key) {
					if (key === "config" && ++queries > 1) throw new Error("SECRET later query");
					return Reflect.getOwnPropertyDescriptor(target, key);
				},
			},
		);
		validateManifests({ modules: [], bootstrapComponents: map as never });
		expect(queries).toBe(1);
	});

	it("reads no inherited config, though an earlier getter deletes the own one: it is none", async () => {
		let inheritedReads = 0;
		const proto = {
			get config(): unknown {
				inheritedReads += 1;
				return withoutIssuer();
			},
		};
		const map = Object.create(proto) as Record<string, unknown>;
		Object.defineProperty(map, "pathResolver", {
			enumerable: true,
			configurable: true,
			get(this: Record<string, unknown>) {
				delete this.config;
				return (p: string) => p;
			},
		});
		Object.defineProperty(map, "config", {
			enumerable: true,
			configurable: true,
			writable: true,
			value: withoutIssuer(),
		});
		// The own config is gone when its key is read: none, refused as such,
		// the inherited getter unread.
		const err = await thrown(viaCreateApp(map));
		expect(err.message).toMatch(/handed no configuration/);
		expect(inheritedReads).toBe(0);
	});

	it("reads a non-enumerable own config, as boot reads the input by its name", () => {
		const map = Object.defineProperty({ pathResolver: (p: string) => p }, "config", {
			value: withoutIssuer(),
			enumerable: false,
		});
		const validated = validateManifests({ modules: [], bootstrapComponents: map as never });
		expect((validated.bootstrapComponents.config as { core?: unknown }).core).toEqual(
			withoutIssuer().core,
		);
	});

	it("answers a map without a prototype, of data properties, leaving the host's map as it was", () => {
		const config = withoutIssuer();
		const pathResolver = (p: string) => p;
		const host = {
			get config(): unknown {
				return config;
			},
			pathResolver,
		};
		const snapshot = snapshotHostMap(host, "bootstrapComponents") as Record<string, unknown>;
		expect(Object.getPrototypeOf(snapshot)).toBeNull();
		expect(Object.getOwnPropertyDescriptor(snapshot, "config")).toHaveProperty("value");
		expect(Object.isFrozen(snapshot.config)).toBe(true);
		expect(snapshot.pathResolver).toBe(pathResolver);
		expect(Object.getOwnPropertyDescriptor(host, "config")?.get).toBeTypeOf("function");
		expect(Object.isFrozen(config)).toBe(false);
		expect(snapshotHostMap(snapshot, "bootstrapComponents")).toBe(snapshot);
	});

	it("keeps own enumerable string-keyed slots, and config and configDefaults of the bootstrap map whatever their enumerability", () => {
		const hidden = (map: object, key: string, value: unknown) =>
			Object.defineProperty(map, key, { value, enumerable: false });
		const bootstrap = hidden(
			hidden({ [Symbol("slot")]: 1, shown: 2 }, "configDefaults", {}),
			"hiddenSlot",
			3,
		);
		expect(Object.keys(snapshotHostMap(bootstrap, "bootstrapComponents")).sort()).toEqual([
			"configDefaults",
			"shown",
		]);
		const override = hidden({ shown: 2 }, "configDefaults", {});
		expect(Object.keys(snapshotHostMap(override, "overrideComponents"))).toEqual(["shown"]);
	});

	it("boots a plain map alike through createApp and a direct validateManifests", async () => {
		const map = { config: withoutIssuer(), pathResolver: (p: string) => p };
		const validated = validateManifests({
			modules: [defineModule({ name: "m" })],
			bootstrapComponents: map as never,
		});
		const handle = await createApp({
			modules: [defineModule({ name: "m" })],
			bootstrapComponents: map as never,
		});
		try {
			expect(handle.components.config).toEqual(validated.bootstrapComponents.config);
			expect(handle.components.pathResolver).toBe(map.pathResolver);
		} finally {
			await handle.dispose();
		}
	});
});
