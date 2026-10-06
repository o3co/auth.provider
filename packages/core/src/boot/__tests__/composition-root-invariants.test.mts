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
 * Integration tests for the composition-root grantPolicy / `oauth.jwt.issuer`
 * invariant: boot fails on a missing, empty or non-canonical issuer, however
 * grantPolicy is wired. No oauth-package module is loaded here, so no section
 * schema parses `oauth {}`: core's stage-1 read of the section refuses a
 * configured issuer that is not canonical (`config-validation-failed`, at the
 * key), and the grant-policy check one that is missing.
 */

import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import type { GrantPolicyHook } from "../../policy/types.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const noopGrantPolicy: GrantPolicyHook = {
	kind: "noop",
	async evaluate() {
		return { outcome: "allow" };
	},
};

// ---------------------------------------------------------------------------
// grantPolicy / jwt.issuer invariant
// ---------------------------------------------------------------------------

describe("grantPolicy/issuer invariant", () => {
	function configWithIssuer(issuer: string | undefined): ReturnType<typeof makeValidCoreConfig> {
		const base = makeValidCoreConfig();
		const oauth = base.oauth as Record<string, unknown>;
		const jwt = oauth.jwt as Record<string, unknown>;
		const newJwt: Record<string, unknown> = { ...jwt };
		if (issuer === undefined) {
			delete newJwt.issuer;
		} else {
			newJwt.issuer = issuer;
		}
		return {
			...base,
			oauth: { ...oauth, jwt: newJwt },
		} as ReturnType<typeof makeValidCoreConfig>;
	}

	const grantPolicyModule = defineModule({
		name: "test-grant-policy-provider",
		provides: {
			grantPolicy: () => noopGrantPolicy,
		},
	});

	const refusedForIssuer = (err: unknown): boolean =>
		err instanceof BootError &&
		err.reason === "grant-policy-without-issuer" &&
		err.stage === "validateManifests";

	/** Refused by core's stage-1 read of `oauth {}`, at the key, before any grant-policy check. */
	const refusedAtTheKey = (err: unknown): boolean =>
		err instanceof BootError &&
		err.reason === "config-validation-failed" &&
		err.stage === "validateManifests" &&
		/oauth\.jwt\.issuer: oauth\.jwt\.issuer must/.test(err.message);

	it("rejects grantPolicy module when config.oauth.jwt.issuer is missing", async () => {
		await expect(
			createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy(refusedForIssuer);
	});

	it("rejects grantPolicy module when issuer is an empty string", async () => {
		await expect(
			createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(""),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy(refusedAtTheKey);
	});

	it.each([
		["http on a host that is not loopback", "http://auth.example"],
		["a query", "https://auth.example?tenant=a"],
		["a fragment", "https://auth.example#top"],
		["credentials", "https://user:secret@auth.example"],
		["a trailing slash", "https://auth.example/"],
		["no scheme", "issuer.internal:8443"],
	])(
		"rejects grantPolicy module when the issuer has %s, naming why and never the value",
		async (_, issuer) => {
			const err = await createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(issuer),
					pathResolver: (p: string) => p,
				} as never,
			}).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toSatisfy(refusedAtTheKey);
			expect((err as BootError).message).not.toContain(issuer);
		},
	);

	it("rejects a non-canonical issuer whichever source wires grantPolicy", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer("http://auth.example"),
					pathResolver: (p: string) => p,
					grantPolicy: noopGrantPolicy,
				} as never,
			}),
		).rejects.toSatisfy(refusedAtTheKey);
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer("https://auth.example/"),
					pathResolver: (p: string) => p,
				} as never,
				overrideComponents: { grantPolicy: noopGrantPolicy } as never,
			}),
		).rejects.toSatisfy(refusedAtTheKey);
	});

	it("accepts grantPolicy module when issuer is a canonical issuer", async () => {
		for (const issuer of [
			"https://auth.example",
			"https://auth.example/tenant",
			"http://localhost:3000",
		]) {
			const handle = await createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(issuer),
					pathResolver: (p: string) => p,
				} as never,
			});
			expect(handle).toBeDefined();
			await handle.dispose();
		}
	});

	it("boots without an issuer when nothing wires grantPolicy and no module owns oauth {}", async () => {
		// Core's schema declares `core` alone: the issuer is the oauth
		// module's to require, and that module's section refuses a missing
		// one. A composition with neither reads no issuer.
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: configWithIssuer(undefined),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(handle).toBeDefined();
		await handle.dispose();
	});

	// The check must also fire when grantPolicy is wired via
	// bootstrapComponents or overrideComponents, the other two paths into the
	// typed DI graph: a module-only scan would let an empty issuer through
	// whenever the host pre-seeds grantPolicy directly.
	it("rejects bootstrapComponents.grantPolicy when issuer is missing", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
					grantPolicy: noopGrantPolicy,
				} as never,
			}),
		).rejects.toSatisfy(refusedForIssuer);
	});

	it("rejects overrideComponents.grantPolicy when issuer is empty", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer(""),
					pathResolver: (p: string) => p,
				} as never,
				overrideComponents: {
					grantPolicy: noopGrantPolicy,
				} as never,
			}),
		).rejects.toSatisfy(refusedAtTheKey);
	});

	it("accepts bootstrapComponents.grantPolicy when issuer is set", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: configWithIssuer("https://auth.example"),
				pathResolver: (p: string) => p,
				grantPolicy: noopGrantPolicy,
			} as never,
		});
		expect(handle).toBeDefined();
		await handle.dispose();
	});
});
