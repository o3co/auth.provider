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
 * #496 — the boot refusals this package added have to be reachable from the
 * configuration path `packages/core/README.md` documents.
 *
 * That path is two parses, not one: a composition root builds its config with
 * `AppConfigSchema.parse(...)` and hands the result to `createApp`, which
 * composes every module's own `configSchema` over `CoreConfigSchema` and
 * parses again. `AppConfigSchema` strips what it does not declare, and until
 * #496 it declared no `oauth.mtls` — so the second parse never saw the
 * operator's block, `enabled` fell to its `false` default, and the module
 * contributed nothing. mTLS reported itself as switched off rather than as
 * misconfigured, and every refusal added this cycle (#431, #469, #470) was
 * unreachable: the configuration they inspect had been thrown away one step
 * earlier.
 *
 * These tests run both parses in that order and then ask the module what it
 * makes of the result.
 */

import { AppConfigSchema, composeConfigSchema } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { mtlsConfigSchema, mtlsModule } from "#/module.mjs";

/** The documented composition root: pre-parse, then boot's composed parse. */
function throughDocumentedPath(mtls: Record<string, unknown>): unknown {
	const base = makeValidAppConfig();
	const preParsed = AppConfigSchema.parse({
		...base,
		oauth: { ...base.oauth, mtls },
	});
	return composeConfigSchema([mtlsConfigSchema]).parse(preParsed);
}

/** `mtlsModule`'s single `tokenBindingMechanisms` contribution. */
function contributeMechanism(config: unknown): unknown {
	const [factory] = mtlsModule.contributes?.tokenBindingMechanisms ?? [];
	if (!factory) throw new Error("mtlsModule no longer contributes a token-binding mechanism");
	return (factory as (deps: { config: unknown }) => unknown)({ config });
}

describe("oauth.mtls reaches the module through the documented config path (#496)", () => {
	it("survives the pre-parse instead of arriving as the disabled default", () => {
		const config = throughDocumentedPath({
			enabled: true,
			source: "tls-layer",
			mode: "self-signed",
		}) as { oauth: { mtls: { enabled: boolean; mode: string } } };
		expect(config.oauth.mtls.enabled).toBe(true);
		expect(config.oauth.mtls.mode).toBe("self-signed");
	});

	it("contributes a mechanism, where a stripped block contributed none", () => {
		const config = throughDocumentedPath({ enabled: true, mode: "self-signed" });
		expect(contributeMechanism(config)).not.toBeNull();
	});

	it("reaches the empty-allowed-hosts refusal under a fetching revocation mode (#431, #470)", () => {
		const config = throughDocumentedPath({
			enabled: true,
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
			"full-pki": { revocation: { mode: "crl", "on-unavailable": "reject" } },
		});
		expect(() => contributeMechanism(config)).toThrow(/non-empty oauth\.mtls\.full-pki/);
	});

	it("reaches the undeclared-revocation refusal under full-pki (#341)", () => {
		const config = throughDocumentedPath({
			enabled: true,
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
		});
		expect(() => contributeMechanism(config)).toThrow(/requires oauth\.mtls\.full-pki\.revocation/);
	});

	it("reaches the empty-trusted-proxies refusal under a header source (#280)", () => {
		const config = throughDocumentedPath({ enabled: true, source: "header" });
		expect(() => contributeMechanism(config)).toThrow(/trusted-proxies allowlist/);
	});

	it("still contributes nothing when the operator leaves mTLS off", () => {
		const base = makeValidAppConfig();
		const config = composeConfigSchema([mtlsConfigSchema]).parse(AppConfigSchema.parse(base));
		expect(contributeMechanism(config)).toBeNull();
	});
});
