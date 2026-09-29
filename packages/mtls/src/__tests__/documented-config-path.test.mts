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
 * This package's boot refusals must be reachable from the configuration path
 * `packages/core/README.md` documents: the composition root hands `createApp`
 * the configuration it resolved, and boot parses it once, laying every
 * schema's output over what was written. A parse that dropped `oauth.mtls`
 * would let `enabled` fall to its `false` default: mTLS would report itself
 * switched off rather than misconfigured, and every refusal would be
 * unreachable. These tests boot `mtlsModule` that way and ask it what it makes
 * of the result, at boot, where its refusals are.
 */

import { type AppConfig, BootError, createApp } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { mtlsModule } from "#/module.mjs";

/**
 * The documented composition root: the resolved configuration with the
 * operator's `oauth.mtls` block, handed to `createApp`. Answers the
 * configuration boot parsed, or the boot's refusal with every cause it
 * carries as one text.
 */
async function throughDocumentedPath(
	mtls: Record<string, unknown> | undefined,
): Promise<{ readonly config: unknown } | { readonly refused: string }> {
	const base = makeValidAppConfig();
	const resolved = mtls === undefined ? base : { ...base, oauth: { ...base.oauth, mtls } };
	try {
		const handle = await createApp({
			modules: [mtlsModule],
			bootstrapComponents: {
				config: resolved as unknown as AppConfig,
				pathResolver: (s: string) => s,
			},
		});
		const config = handle.components.config;
		await handle.dispose();
		return { config };
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		const texts: string[] = [];
		for (let at: unknown = err; at instanceof Error; at = at.cause) texts.push(at.message);
		return { refused: texts.join("\n") };
	}
}

/** `mtlsModule`'s single `tokenBindingMechanisms` contribution. */
function contributeMechanism(config: unknown): unknown {
	const [factory] = mtlsModule.contributes?.tokenBindingMechanisms ?? [];
	if (!factory) throw new Error("mtlsModule no longer contributes a token-binding mechanism");
	return (factory as (deps: { config: unknown }) => unknown)({ config });
}

/** The configuration boot parsed, failing the test when boot refused. */
async function booted(mtls: Record<string, unknown> | undefined): Promise<unknown> {
	const result = await throughDocumentedPath(mtls);
	if (!("config" in result)) return expect.fail(`boot refused: ${result.refused}`);
	return result.config;
}

/** The boot's refusal, failing the test when boot succeeded. */
async function refusedWith(mtls: Record<string, unknown>): Promise<string> {
	const result = await throughDocumentedPath(mtls);
	if (!("refused" in result)) return expect.fail("boot should have been refused");
	return result.refused;
}

describe("oauth.mtls reaches the module through the documented config path", () => {
	it("survives boot's parse instead of arriving as the disabled default", async () => {
		const config = (await booted({
			enabled: true,
			source: "tls-layer",
			mode: "self-signed",
		})) as { oauth: { mtls: { enabled: boolean; mode: string } } };
		expect(config.oauth.mtls.enabled).toBe(true);
		expect(config.oauth.mtls.mode).toBe("self-signed");
	});

	it("contributes a mechanism, where a stripped block contributed none", async () => {
		const config = await booted({ enabled: true, mode: "self-signed" });
		expect(contributeMechanism(config)).not.toBeNull();
	});

	it("reaches the empty-allowed-hosts refusal under a fetching revocation mode", async () => {
		const refused = await refusedWith({
			enabled: true,
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
			"full-pki": { revocation: { mode: "crl", "on-unavailable": "reject" } },
		});
		expect(refused).toMatch(/non-empty oauth\.mtls\.full-pki/);
	});

	it("reaches the undeclared-revocation refusal under full-pki", async () => {
		const refused = await refusedWith({
			enabled: true,
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
		});
		expect(refused).toMatch(/requires oauth\.mtls\.full-pki\.revocation/);
	});

	it("reaches the empty-trusted-proxies refusal under a header source", async () => {
		const refused = await refusedWith({ enabled: true, source: "header" });
		expect(refused).toMatch(/trusted-proxies allowlist/);
	});

	it("still contributes nothing when the operator leaves mTLS off", async () => {
		expect(contributeMechanism(await booted(undefined))).toBeNull();
	});
});
