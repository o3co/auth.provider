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
 * A federation's provider, built by the factory of the type its
 * `core.federations` entry names, is a provider named after the entry: the
 * session finds the federation's redirect policy and callback URL by the
 * provider's name, so a provider named otherwise would be served at the
 * entry with another federation's policy and callback URL. Anything else is
 * a failed contribution (`federation-types.test.mts` pins the cleanups and
 * that neither half of the pair registers).
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

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

/** The six slots an enabled federation needs wired (`federation-stores-wiring`). */
const federationStores = defineModule({
	name: "test:federation-stores",
	provides: {
		userSessionStore: () => ({ kind: "stub" }),
		sessionRPRegistry: () => ({ kind: "stub" }),
		sessionFamilyIndex: () => ({ kind: "stub" }),
		sessionFederationIndex: () => ({ kind: "stub" }),
		federationTokenStore: () => ({ kind: "stub" }),
		refreshTokenFamilyRevocation: () => ({ kind: "stub" }),
	} as never,
});

/** A federation package handling the type `acme`, whose factory answers `provider()`. */
const acmeAnswering = (provider: () => unknown) =>
	defineModule({
		name: "federation-acme",
		contributes: {
			federationTypes: {
				acme: {
					entrySchema: z.object({}),
					factory: provider as never,
					redirectPolicy: policy as never,
				},
			},
		},
	});

/** One enabled entry of the type `acme`, named `name`. */
const entryNamed = (name: string): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			...coreConfigForTests({
				federations: {
					[name]: {
						enabled: true,
						type: "acme",
						callbackURL: `https://auth.example/session/federation/${name}/callback`,
					},
				} as never,
			}),
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

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

describe("a federation's provider is named after its entry", () => {
	it.each<readonly [string, () => unknown]>([
		["nothing", () => undefined],
		["null", () => null],
		["a string", () => "legacy"],
		["a number", () => 7],
		["a provider without a name", () => providerNamed(undefined)],
		["a provider whose name is not a string", () => providerNamed(7)],
		["a provider named after another entry", () => providerNamed("corp")],
		["a list", () => ["legacy"]],
	])(
		"refuses a type's factory answering %s, as a failed contribution",
		async (_answer, provider) => {
			const err = await refusal(
				createApp({
					modules: [federationStores, acmeAnswering(provider)],
					bootstrapComponents: entryNamed("legacy"),
				}),
			);

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.stage).toBe("applyContributions");
			expect(err.details).toMatchObject({
				module: "federation-acme",
				kind: "federations",
				name: "legacy",
			});
			expect(err.message).toContain('"legacy"');
		},
	);

	it("boots a provider named after its entry", async () => {
		const answered = providerNamed("legacy");

		const handle = await createApp({
			modules: [federationStores, acmeAnswering(() => answered)],
			bootstrapComponents: entryNamed("legacy"),
		});

		expect(handle.components.federationProviders?.get("legacy")).toBe(answered);
		await handle.dispose();
	});

	it("quotes the provider's name only as JSON, and nothing else of the provider", async () => {
		const answeredName = 'corp "idp"\nnext line';
		const err = await refusal(
			createApp({
				modules: [
					federationStores,
					acmeAnswering(() => providerNamed(answeredName, { clientSecret: "s3cret-value" })),
				],
				bootstrapComponents: entryNamed("corp.idp"),
			}),
		);

		const thrown = (err.details as { originalError?: unknown }).originalError;
		expect(thrown).toBeInstanceOf(RangeError);
		const { message } = thrown as RangeError;
		expect(message).toContain(JSON.stringify(answeredName));
		expect(message).not.toContain("\n");
		expect(message).not.toContain("s3cret-value");
		expect(err.message).toContain(message);
		expect(err.message).not.toContain("s3cret-value");
	});

	it("does not quote a name that is not a string", async () => {
		const err = await refusal(
			createApp({
				modules: [
					federationStores,
					acmeAnswering(() => providerNamed({ toString: () => "s3cret-value" })),
				],
				bootstrapComponents: entryNamed("legacy"),
			}),
		);

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).not.toContain("s3cret-value");
	});
});
