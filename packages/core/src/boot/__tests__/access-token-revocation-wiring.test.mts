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
 * Boot guard for RFC 7009 access-token revocation (#277, folded onto the
 * declared-absence vocabulary by #375).
 *
 * `POST /oauth/revoke` answering 200 is a security promise. The access-token
 * half of that promise is kept by the `accessTokenDenylist` slot: without one
 * the endpoint verified the token, logged a warning, and returned 200 while
 * the JWT stayed valid everywhere until expiry. An operator revoking a token
 * mid-incident had no way to learn that from the response.
 *
 * #277 turned that into a bespoke stage-1 check ("step 13.9") with its own
 * BootError reason. #375 retires the bespoke check: the modules that read the
 * slot now attach `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY`, and the generic
 * declared-absence guard (#363) enforces it — unfilled slot + config not
 * saying `oauth.revocation.accessToken = "unsupported"` → boot refuses with
 * `component-absence-undeclared`. Omission of the config key means NOT
 * declared, which preserves 13.9's reading: every config written before #277
 * omits the key, and those are exactly the deployments whose revocation
 * endpoint answered 200 with nothing behind it.
 *
 * One deliberate semantic move: the trigger is now the POLICY on the reading
 * module's manifest, not core hardcoding the key. A hand-built module that
 * reads the slot without attaching the policy no longer trips the guard —
 * attaching the policy is the statement that denylist-backed revocation is
 * part of the app's surface, and the bundled `oauthModule` /
 * `tokenExchangeModule` both make it.
 */
import { describe, expect, it } from "vitest";
import { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY, createApp, defineModule } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/**
 * Stand-in for `oauthModule` / `tokenExchangeModule`: reads
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

describe("access-token revocation wiring (#277 via the declared-absence guard)", () => {
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
		// `"denylist"` stated out loud is not a declaration of absence — it is
		// the promise that needs the slot. Same reading 13.9 had for it.
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
