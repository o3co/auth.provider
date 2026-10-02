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
 * A federation a module contributes or overrides directly, by its key
 * (`federations.<key>`), is a provider named after that key: the session
 * finds the federation's redirect policy and callback URL by the provider's
 * name, so a provider registered under another key would be served at that
 * key with another federation's policy and callback URL. Anything else is a
 * failed contribution, as for an entry dispatched by its type
 * (`federation-types.test.mts`).
 */

import { describe, expect, it, vi } from "vitest";
import type { FederationProvider } from "../../federations/types.mjs";
import type { Module } from "../../modules/manifest/index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

const minBoot = (): BootstrapMap =>
	({
		config: makeValidCoreConfig(),
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

const providerNamed = (name: unknown, extra: Record<string, unknown> = {}): FederationProvider =>
	({
		name,
		scope: ["openid"],
		buildAuthorizationUrl: () => new URL("https://idp.example/authorize"),
		exchangeCode: async () => ({ issuer: "https://idp.example", sub: "1", expiresAt: null }),
		...extra,
	}) as FederationProvider;

const policy = () => ({
	validateRedirect: () => ({ ok: true as const, value: undefined }),
	resolveCallbackRedirect: () => ({ ok: true as const, value: "https://app.example" }),
});

/** A module contributing `federations.<key>`, answered by `provider`, and its redirect policy. */
const contributing = (moduleName: string, key: string, provider: () => unknown): Module =>
	defineModule({
		name: moduleName,
		contributes: {
			federations: { [key]: provider },
			federationRedirectPolicies: { [key]: policy },
		} as never,
	});

/** A module overriding `federations.<key>` with `provider`. */
const overriding = (moduleName: string, key: string, provider: () => unknown): Module =>
	defineModule({
		name: moduleName,
		overrides: { federations: { [key]: provider } } as never,
	});

/**
 * The modules that register `provider` under `key`: one module contributing
 * it, or a module contributing a well-named provider and a second
 * overriding it with `provider`. The module whose factory answers
 * `provider` is `test:answering`.
 */
const registering = (
	path: "contributes" | "overrides",
	key: string,
	provider: () => unknown,
): Module[] =>
	path === "contributes"
		? [contributing("test:answering", key, provider)]
		: [
				contributing("test:contributing", key, () => providerNamed(key)),
				overriding("test:answering", key, provider),
			];

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

const PATHS = ["contributes", "overrides"] as const;

describe("federations contributed directly — the provider is named after its key", () => {
	it.each(PATHS)(
		"refuses a provider named otherwise than its key when a module %s it, as a failed contribution, after the cleanups, registering nothing",
		async (path) => {
			const cleanup = vi.fn();
			const closing = defineModule({
				name: "test:closing",
				provides: { closingSlot: () => 1 },
				lifecycle: { closingSlot: { eager: true, cleanup } },
			} as never);
			const { federations, federationRedirectPolicies } = mergeWithBuiltins(undefined);

			const err = await refusal(
				createApp({
					modules: [closing, ...registering(path, "legacy", () => providerNamed("corp"))],
					bootstrapComponents: minBoot(),
					contributionKinds: { federations, federationRedirectPolicies },
				}),
			);

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.stage).toBe("applyContributions");
			expect(err.details).toMatchObject({
				reason: "contribute-factory-failed",
				module: "test:answering",
				kind: "federations",
				name: "legacy",
			});
			expect(err.message).toContain("federations.legacy");
			expect(err.message).toContain('"corp"');
			expect(cleanup).toHaveBeenCalledOnce();
			// Nothing is served at the key under another federation's name.
			const registered = federations?.get("legacy");
			expect(registered === undefined || registered.name === "legacy").toBe(true);
		},
	);

	it.each(
		PATHS.flatMap((path) =>
			(
				[
					["nothing", () => undefined],
					["null", () => null],
					["a string", () => "legacy"],
					["a number", () => 7],
					["a provider without a name", () => providerNamed(undefined)],
					["a provider whose name is not a string", () => providerNamed(7)],
					["a list", () => ["legacy"]],
				] as const
			).map(([answer, provider]) => [path, answer, provider] as const),
		),
	)("refuses, when a module %s it, a factory answering %s", async (path, _answer, provider) => {
		const err = await refusal(
			createApp({
				modules: registering(path, "legacy", provider),
				bootstrapComponents: minBoot(),
			}),
		);

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:answering",
			kind: "federations",
			name: "legacy",
		});
		expect(err.message).toContain("federations.legacy");
	});

	it.each(PATHS)("boots a provider named after its key when a module %s it", async (path) => {
		const answered = providerNamed("legacy");

		const handle = await createApp({
			modules: registering(path, "legacy", () => answered),
			bootstrapComponents: minBoot(),
		});

		expect(handle.components.federationProviders?.get("legacy")).toBe(answered);
		await handle.dispose();
	});

	it("quotes the key as a path, bare when it is a bare key and as JSON otherwise, and the provider's name only as JSON, and nothing else of the provider", async () => {
		const answeredName = 'corp "idp"\nnext line';
		const err = await refusal(
			createApp({
				modules: registering("contributes", "corp.idp", () =>
					providerNamed(answeredName, { clientSecret: "s3cret-value" }),
				),
				bootstrapComponents: minBoot(),
			}),
		);

		const thrown = (err.details as { originalError?: unknown }).originalError;
		expect(thrown).toBeInstanceOf(RangeError);
		const { message } = thrown as RangeError;
		expect(message.startsWith('federations."corp.idp": ')).toBe(true);
		expect(message).toContain(JSON.stringify(answeredName));
		expect(message).not.toContain("\n");
		expect(message).not.toContain("s3cret-value");
		expect(err.message).toContain(message);
		expect(err.message).not.toContain("s3cret-value");

		const bare = await refusal(
			createApp({
				modules: registering("overrides", "corp_idp-2", () => providerNamed("corp")),
				bootstrapComponents: minBoot(),
			}),
		);
		expect(
			((bare.details as { originalError?: unknown }).originalError as RangeError).message,
		).toMatch(/^federations\.corp_idp-2: /);
	});

	it("does not quote a name that is not a string", async () => {
		const err = await refusal(
			createApp({
				modules: registering("contributes", "legacy", () =>
					providerNamed({ toString: () => "s3cret-value" }),
				),
				bootstrapComponents: minBoot(),
			}),
		);

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).not.toContain("s3cret-value");
	});
});
