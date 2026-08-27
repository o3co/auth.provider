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
 * Boot guard for RFC 7009 access-token revocation (#277).
 *
 * `POST /oauth/revoke` answering 200 is a security promise. The access-token
 * half of that promise is kept by the `accessTokenDenylist` slot: without one
 * the endpoint verified the token, logged a warning, and returned 200 while
 * the JWT stayed valid everywhere until expiry. An operator revoking a token
 * mid-incident had no way to learn that from the response.
 *
 * The guard turns that into a boot failure, so the deploy fails instead of the
 * incident response.
 */
import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/**
 * Stand-in for `oauthModule`: a module that reads `accessTokenDenylist`
 * opportunistically. That declaration is the composition-level signal that the
 * denylist is part of this app's token surface — core cannot see route
 * mount paths, so consuming the slot is what it keys on.
 */
const denylistConsumerModule = defineModule({
	name: "test:denylist-consumer",
	optional: ["accessTokenDenylist"] as const,
});

const denylistProviderModule = defineModule({
	name: "test:denylist-provider",
	provides: {
		accessTokenDenylist: () => ({
			kind: "stub",
			add: async () => {},
			has: async () => false,
		}),
	} as never,
});

function boot(configOverrides: Record<string, unknown> = {}) {
	return {
		config: { ...makeValidAppConfig(), ...configOverrides },
		pathResolver: (p: string) => p,
	} as never;
}

function withRevocation(accessToken: "denylist" | "unsupported") {
	const base = makeValidAppConfig();
	return { oauth: { ...base.oauth, revocation: { accessToken } } };
}

describe("checkAccessTokenRevocationWiring", () => {
	it("fails boot when a module consumes accessTokenDenylist but nothing provides it", async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(),
			}),
		).rejects.toThrow(BootError);

		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(),
			}),
		).rejects.toMatchObject({
			reason: "access-token-revocation-unenforceable",
			details: {
				reason: "access-token-revocation-unenforceable",
				consumedBy: ["test:denylist-consumer"],
			},
		});
	});

	it("names the two ways out in the message", async () => {
		const err = await createApp({
			modules: [denylistConsumerModule],
			bootstrapComponents: boot(),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).message).toContain("accessTokenDenylist");
		expect((err as BootError).message).toContain('oauth.revocation.accessToken = "unsupported"');
	});

	it("passes when a module provides the denylist", async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule, denylistProviderModule],
				bootstrapComponents: boot(),
			}),
		).resolves.toBeDefined();
	});

	it("passes when the denylist arrives through bootstrapComponents", async () => {
		const bootstrap = {
			...(boot() as Record<string, unknown>),
			accessTokenDenylist: { kind: "stub", add: async () => {}, has: async () => false },
		} as never;
		await expect(
			createApp({ modules: [denylistConsumerModule], bootstrapComponents: bootstrap }),
		).resolves.toBeDefined();
	});

	it("passes when the denylist arrives through overrideComponents", async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(),
				overrideComponents: {
					accessTokenDenylist: { kind: "stub", add: async () => {}, has: async () => false },
				} as never,
			}),
		).resolves.toBeDefined();
	});

	it('passes without a denylist when the operator declares access-token revocation "unsupported"', async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(withRevocation("unsupported")),
			}),
		).resolves.toBeDefined();
	});

	it("still fails when the operator spells out the default explicitly", async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(withRevocation("denylist")),
			}),
		).rejects.toMatchObject({ reason: "access-token-revocation-unenforceable" });
	});

	it("stays silent for a composition that never reads the slot", async () => {
		// A session-only / token-only deployment mounts no revocation endpoint.
		// The guard must not turn every such app into a boot failure.
		await expect(createApp({ modules: [], bootstrapComponents: boot() })).resolves.toBeDefined();
	});
});
