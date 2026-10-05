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
 * Boot guard for RFC 7009 access-token revocation, on the declared-absence
 * guard.
 *
 * `POST /oauth/revoke` answering 200 is a security promise, and the
 * `accessTokenDenylist` slot keeps its access-token half: without it the JWT
 * stays valid everywhere until expiry, and an operator revoking a token
 * mid-incident cannot learn that from the response.
 *
 * Modules that read the slot attach `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY`:
 * unfilled slot + config not saying `oauth.revocation.accessToken =
 * "unsupported"` → boot refuses with `component-absence-undeclared`. An
 * omitted config key means NOT declared.
 *
 * The trigger is the policy on the reading module's manifest, not a key core
 * hardcodes: a hand-built module that reads the slot without attaching the
 * policy does not trip the guard. The bundled `oauthEndpointsModule` /
 * `tokenExchangeModule` both attach it.
 */
import { describe, expect, it } from "vitest";
import { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY, createApp, defineModule } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/**
 * Stand-in for `oauthEndpointsModule` / `tokenExchangeModule`: reads
 * `accessTokenDenylist` opportunistically and attaches the shared policy —
 * the declaration that denylist-backed revocation is part of this app's
 * surface.
 */
const denylistConsumerModule = defineModule({
	name: "test:denylist-consumer",
	optional: ["accessTokenDenylist"] as const,
	absencePolicies: { accessTokenDenylist: ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY },
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

describe("access-token revocation wiring through the declared-absence guard", () => {
	it("fails boot when a module carries the policy but nothing provides the denylist", async () => {
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(),
			}),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				reason: "component-absence-undeclared",
				componentKey: "accessTokenDenylist",
				consumedBy: ["test:denylist-consumer"],
				configKey: "oauth.revocation.accessToken",
				absentValue: "unsupported",
			},
		});
	});

	it("names the two ways out in the message, RFC 7009 stakes included", async () => {
		const err = await createApp({
			modules: [denylistConsumerModule],
			bootstrapComponents: boot(),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).message).toContain("accessTokenDenylist");
		expect((err as BootError).message).toContain('oauth.revocation.accessToken = "unsupported"');
		// The stakes travel in the policy hint: what the 200 would silently mean.
		expect((err as BootError).message).toContain("RFC 7009");
		expect((err as BootError).message).toContain("Refresh-token revocation");
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
		// `"denylist"` stated out loud is not a declaration of absence: it is
		// the promise that needs the slot.
		await expect(
			createApp({
				modules: [denylistConsumerModule],
				bootstrapComponents: boot(withRevocation("denylist")),
			}),
		).rejects.toMatchObject({ reason: "component-absence-undeclared" });
	});

	it("stays silent for a composition that never reads the slot", async () => {
		// A session-only / token-only deployment mounts no revocation endpoint.
		// The guard must not turn every such app into a boot failure.
		await expect(createApp({ modules: [], bootstrapComponents: boot() })).resolves.toBeDefined();
	});
});
