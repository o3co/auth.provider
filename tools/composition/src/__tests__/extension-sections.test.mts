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
 * The sections of `dpop`, `mtls`, `device-grant` and `oauth-token-exchange`,
 * each under its module's name, through the template's own reading of the
 * full set: the operator's layer and environment read once, phase one's
 * switches, then the layers over every loaded package's `reference.conf`
 * handed to boot. Each section is read at its new path and refuses a key it
 * does not declare; a path it moved from refuses boot naming the new one;
 * each DPoP nonce variable renamed with the move refuses boot unless its new
 * name carries the same value.
 */

import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { BootError } from "@o3co/auth-provider-core";
import {
	basic,
	DISCOVERY_PATHS,
	ISSUER,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import {
	BINDER,
	CLIENT_CERTIFICATE,
	composeFullSet,
	dpopProof,
	type FullSet,
	type FullSetOptions,
	TV,
} from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots the full set, the operator's layer and environment as given, and remembers it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

/** What boot refused the full set with. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** A nonce secret of 32 random bytes, as `openssl rand -base64 32` makes one. */
const secret = (): string => randomBytes(32).toString("base64");

/** A section the parsed configuration holds, by its top-level name. */
const sectionOf = (composition: FullSet, name: string): unknown =>
	(composition.config as unknown as Record<string, unknown>)[name];

const payloadOf = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString()) as Record<
		string,
		unknown
	>;

describe("each section read at its module's name, through the template's reading", () => {
	it("dpop: advertises the algorithms dpop.algWhitelist lists", async () => {
		const { app } = await boot({ operatorHocon: 'dpop.algWhitelist = ["ES256"]\n' });

		const res = await request(app).get(DISCOVERY_PATHS[0]);
		expect(res.body.dpop_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("dpop: asks the token endpoint's caller for a nonce when DPOP_NONCE_REQUIRED and DPOP_NONCE_SECRET say so", async () => {
		const { app } = await boot({
			env: { ...SINGLE_ENV, DPOP_NONCE_REQUIRED: "as", DPOP_NONCE_SECRET: secret() },
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(BINDER))
			.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
			.type("form")
			.send({ grant_type: "client_credentials" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("use_dpop_nonce");
		expect(typeof res.headers["dpop-nonce"]).toBe("string");
	});

	it("mtls: binds the token to the certificate forwarded in the header mtls.certHeader names", async () => {
		const { app } = await boot({ operatorHocon: 'mtls.certHeader = "x-client-certificate"\n' });
		const token = (header: string) =>
			request(app)
				.post("/oauth/token")
				.set("Authorization", basic(BINDER))
				.set(header, encodeURIComponent(CLIENT_CERTIFICATE))
				.type("form")
				.send({ grant_type: "client_credentials" });

		const named = await token("x-client-certificate");
		expect(named.status).toBe(200);
		expect(payloadOf(named.body.access_token as string).cnf).toEqual({
			"x5t#S256": createHash("sha256")
				.update(new X509Certificate(CLIENT_CERTIFICATE).raw)
				.digest("base64url"),
		});
		const other = await token("x-forwarded-client-cert");
		expect(other.status).toBe(200);
		expect(payloadOf(other.body.access_token as string).cnf).toBeUndefined();
	});

	it("device-grant: gives a device code the lifetime device-grant.codeLifetimeSeconds sets", async () => {
		const { app } = await boot({ operatorHocon: "device-grant.codeLifetimeSeconds = 900\n" });

		const res = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(res.status).toBe(200);
		expect(res.body.expires_in).toBe(900);
	});

	it("oauth-token-exchange: reads maxActorChainDepth from its section, and from OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH", async () => {
		const written = await boot({ operatorHocon: "oauth-token-exchange.maxActorChainDepth = 2\n" });
		expect(sectionOf(written, "oauth-token-exchange")).toEqual({ maxActorChainDepth: 2 });
		await written.handle.dispose();

		const variable = await boot({
			env: { ...SINGLE_ENV, OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH: "5" },
		});
		expect(sectionOf(variable, "oauth-token-exchange")).toEqual({ maxActorChainDepth: 5 });
	});

	it("leaves nothing at the paths the sections moved from", async () => {
		const composition = await boot();

		const oauth = (composition.resolved as unknown as { oauth: Record<string, unknown> }).oauth;
		for (const old of ["dpop", "mtls", "deviceAuthorization", "tokenExchange"]) {
			expect(oauth, old).not.toHaveProperty(old);
		}
	});
});

describe("a path a section moved from, written in the operator's own layer", () => {
	/** Every key written at the old path, refused as moved: `[from, to, variable?]` each. */
	const refusedAs = async (hocon: string) => {
		const err = await refused({ operatorHocon: hocon });
		expect(err.reason).toBe("config-path-relocated");
		const { relocated } = err.details as unknown as {
			relocated: { module: string; from: string; to: string | null; environmentVariable?: string }[];
		};
		return relocated;
	};

	it("oauth.dpop: every key refused, naming its path under dpop and the variable bound there", async () => {
		const relocated = await refusedAs(
			[
				"oauth.dpop {",
				"  enabled = true",
				"  iat-window-seconds = 30",
				'  alg-whitelist = ["ES256"]',
				"  replay-store-ttl-seconds = 120",
				'  replay-store = "redis"',
				'  nonce { required = "as", ttl-seconds = 60, secret = "old-secret-5e2d" }',
				"}",
				"",
			].join("\n"),
		);

		expect(relocated).toHaveLength(8);
		expect(relocated).toEqual(
			expect.arrayContaining([
				{ module: "dpop", from: "oauth.dpop.enabled", to: "dpop.enabled" },
				{ module: "dpop", from: "oauth.dpop.iat-window-seconds", to: "dpop.iatWindowSeconds" },
				{ module: "dpop", from: "oauth.dpop.alg-whitelist", to: "dpop.algWhitelist" },
				{
					module: "dpop",
					from: "oauth.dpop.replay-store-ttl-seconds",
					to: "dpop.replayStoreTtlSeconds",
				},
				{ module: "dpop", from: "oauth.dpop.replay-store", to: null },
				{
					module: "dpop",
					from: "oauth.dpop.nonce.required",
					to: "dpop.nonce.required",
					environmentVariable: "DPOP_NONCE_REQUIRED",
				},
				{
					module: "dpop",
					from: "oauth.dpop.nonce.ttl-seconds",
					to: "dpop.nonce.ttlSeconds",
					environmentVariable: "DPOP_NONCE_TTL_SECONDS",
				},
				{
					module: "dpop",
					from: "oauth.dpop.nonce.secret",
					to: "dpop.nonce.secret",
					environmentVariable: "DPOP_NONCE_SECRET",
				},
			]),
		);
	});

	it("oauth.mtls: every key refused, naming its camelCase path under mtls and no variable", async () => {
		const relocated = await refusedAs(
			[
				"oauth.mtls {",
				"  enabled = true",
				'  source = "header"',
				'  cert-header = "x-client-cert"',
				'  cert-header-dialect = "envoy"',
				'  trusted-proxies = ["loopback"]',
				'  mode = "full-pki"',
				'  trusted-cas = ["file:/ca.pem"]',
				"  full-pki {",
				"    max-chain-depth = 4",
				'    signature-algorithms = ["ed25519"]',
				"    min-rsa-key-bits = 3072",
				"    revocation {",
				'      mode = "crl"',
				'      on-unavailable = "reject"',
				'      allowed-hosts = ["crl.example.com"]',
				"      fetch-timeout-ms = 1000",
				"      cache-ttl-seconds = 60",
				"      max-response-bytes = 1024",
				"      ocsp-require-nonce = false",
				"    }",
				"  }",
				"}",
				"",
			].join("\n"),
		);

		const moved = (from: string, to: string) => ({ module: "mtls", from: `oauth.mtls.${from}`, to });
		expect(relocated).toHaveLength(17);
		expect(relocated).toEqual(
			expect.arrayContaining([
				moved("enabled", "mtls.enabled"),
				moved("source", "mtls.source"),
				moved("cert-header", "mtls.certHeader"),
				moved("cert-header-dialect", "mtls.certHeaderDialect"),
				moved("trusted-proxies", "mtls.trustedProxies"),
				moved("mode", "mtls.mode"),
				moved("trusted-cas", "mtls.trustedCas"),
				moved("full-pki.max-chain-depth", "mtls.fullPki.maxChainDepth"),
				moved("full-pki.signature-algorithms", "mtls.fullPki.signatureAlgorithms"),
				moved("full-pki.min-rsa-key-bits", "mtls.fullPki.minRsaKeyBits"),
				moved("full-pki.revocation.mode", "mtls.fullPki.revocation.mode"),
				moved("full-pki.revocation.on-unavailable", "mtls.fullPki.revocation.onUnavailable"),
				moved("full-pki.revocation.allowed-hosts", "mtls.fullPki.revocation.allowedHosts"),
				moved("full-pki.revocation.fetch-timeout-ms", "mtls.fullPki.revocation.fetchTimeoutMs"),
				moved("full-pki.revocation.cache-ttl-seconds", "mtls.fullPki.revocation.cacheTtlSeconds"),
				moved(
					"full-pki.revocation.max-response-bytes",
					"mtls.fullPki.revocation.maxResponseBytes",
				),
				moved(
					"full-pki.revocation.ocsp-require-nonce",
					"mtls.fullPki.revocation.ocspRequireNonce",
				),
			]),
		);
	});

	it("oauth.deviceAuthorization: every key refused, naming its camelCase path under device-grant and no variable", async () => {
		const relocated = await refusedAs(
			[
				"oauth.deviceAuthorization {",
				"  enabled = true",
				'  verification-uri = "https://auth.test/activate"',
				"  verification-uri-complete = true",
				"  code-lifetime-seconds = 900",
				"  polling-interval-seconds = 10",
				"  rateLimit { limit = 3, windowSeconds = 120 }",
				'  store = "unsupported"',
				"}",
				"",
			].join("\n"),
		);

		const moved = (from: string, to: string) => ({
			module: "device-grant",
			from: `oauth.deviceAuthorization.${from}`,
			to: `device-grant.${to}`,
		});
		expect(relocated).toHaveLength(8);
		expect(relocated).toEqual(
			expect.arrayContaining([
				moved("enabled", "enabled"),
				moved("verification-uri", "verificationUri"),
				moved("verification-uri-complete", "verificationUriComplete"),
				moved("code-lifetime-seconds", "codeLifetimeSeconds"),
				moved("polling-interval-seconds", "pollingIntervalSeconds"),
				moved("rateLimit.limit", "rateLimit.limit"),
				moved("rateLimit.windowSeconds", "rateLimit.windowSeconds"),
				moved("store", "store"),
			]),
		);
	});

	it("oauth.tokenExchange: refused, naming oauth-token-exchange.maxActorChainDepth and its variable", async () => {
		const relocated = await refusedAs("oauth.tokenExchange.maxActorChainDepth = 2\n");

		expect(relocated).toEqual([
			{
				module: "oauth-token-exchange",
				from: "oauth.tokenExchange.maxActorChainDepth",
				to: "oauth-token-exchange.maxActorChainDepth",
				environmentVariable: "OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH",
			},
		]);
	});
});

describe("a key a section does not declare", () => {
	it.each([
		["dpop.iatWindowSecond = 30", "iatWindowSecond"],
		["dpop.nonce.ttl = 60", "ttl"],
		['mtls.certHeaders = "x-client-cert"', "certHeaders"],
		["mtls.fullPki.maxDepth = 4", "maxDepth"],
		['mtls.fullPki.revocation { mode = "crl", onUnavailable = "reject", mod = "x" }', "mod"],
		['device-grant.verificationUrl = "https://auth.test/activate"', "verificationUrl"],
		["device-grant.rateLimit.windowSecond = 60", "windowSecond"],
		["oauth-token-exchange.maxActorDepth = 2", "maxActorDepth"],
	])("%s: refused, naming %s", async (hocon, key) => {
		const err = await refused({ operatorHocon: `${hocon}\n` });

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});
});

describe("a DPoP nonce variable renamed with the move, through the template's reading", () => {
	/** Each renamed variable: its old name, its new name, the path the new one binds, a value, and what that value needs beside it to boot. */
	const ROWS = [
		{
			from: "OAUTH_DPOP_NONCE_REQUIRED",
			to: "DPOP_NONCE_REQUIRED",
			path: "dpop.nonce.required",
			value: "as",
			beside: (): Record<string, string> => ({ DPOP_NONCE_SECRET: secret() }),
		},
		{
			from: "OAUTH_DPOP_NONCE_TTL_SECONDS",
			to: "DPOP_NONCE_TTL_SECONDS",
			path: "dpop.nonce.ttlSeconds",
			value: "600",
			beside: (): Record<string, string> => ({}),
		},
		{
			from: "OAUTH_DPOP_NONCE_SECRET",
			to: "DPOP_NONCE_SECRET",
			path: "dpop.nonce.secret",
			value: secret(),
			beside: (): Record<string, string> => ({}),
		},
	] as const;

	it.each(ROWS)(
		"$from set alone: refused, naming $to and $path",
		async ({ from, to, path, value }) => {
			const err = await refused({ env: { ...SINGLE_ENV, [from]: value } });

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module: "dpop", from, to, path, state: "unset" }],
			});
		},
	);

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async ({ from, to }) => {
			const err = await refused({
				env: { ...SINGLE_ENV, [from]: "old-value-5e2d", [to]: "new-value-c81a" },
			});

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["old-value-5e2d", "new-value-c81a"]) {
				expect(err.message).not.toContain(value);
				expect(JSON.stringify(err.details)).not.toContain(value);
			}
		},
	);

	it.each(ROWS)(
		"$from set beside $to at the same value: boots, the value at $path",
		async ({ from, to, path, value, beside }) => {
			const composition = await boot({
				env: { ...SINGLE_ENV, ...beside(), [from]: value, [to]: value },
			});

			const key = path.split(".").at(-1) as string;
			const nonce = (sectionOf(composition, "dpop") as { nonce: Record<string, unknown> }).nonce;
			expect(String(nonce[key])).toBe(value);
		},
	);
});
