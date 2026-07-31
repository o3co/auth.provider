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

import type { Request } from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { DPoPError } from "#/errors.mjs";
import { createMemoryDPoPReplayStore } from "#/memory/replay-store.mjs";
import { computeJkt } from "#/thumbprint.mjs";
import { createDPoPMechanism } from "#/verifier.mjs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface MintOptions {
	htm?: string;
	htu?: string;
	iat?: number;
	jti?: string;
	alg?: string;
	/** Extra claims to merge into the payload */
	extraClaims?: Record<string, unknown>;
	/** If provided, use this key pair instead of generating a new one */
	keyPair?: Awaited<ReturnType<typeof generateKeyPair>>;
	/** If true, tamper with the signature after signing */
	tamperSignature?: boolean;
}

/**
 * Mint a valid DPoP proof JWT for tests. Returns the compact JWT and the
 * public JWK used to sign it.
 */
const mintProof = async (opts: MintOptions = {}) => {
	const {
		htm = "POST",
		htu = "https://as.example/token",
		iat = Math.floor(Date.now() / 1000),
		jti = crypto.randomUUID(),
		alg = "ES256",
		extraClaims = {},
		tamperSignature = false,
	} = opts;
	const keyPair = opts.keyPair ?? (await generateKeyPair(alg));
	const { publicKey, privateKey } = keyPair;
	const jwk = await exportJWK(publicKey);

	const proof = await new SignJWT({ htm, htu, iat, jti, ...extraClaims })
		.setProtectedHeader({ typ: "dpop+jwt", alg, jwk })
		.sign(privateKey);

	const jkt = await computeJkt(jwk);

	if (tamperSignature) {
		// Flip one character in the signature to produce an invalid JWT.
		const parts = proof.split(".");
		const sig = parts[2];
		// Replace first char with a different char.
		const altered = sig.charAt(0) === "A" ? `B${sig.slice(1)}` : `A${sig.slice(1)}`;
		return { proof: `${parts[0]}.${parts[1]}.${altered}`, jwk, jkt };
	}

	return { proof, jwk, jkt };
};

/**
 * Build a minimal Express-like Request stub for the verifier.
 */
const makeReq = (
	dpopHeader: string | undefined,
	method = "POST",
	path = "/token",
	host = "as.example",
	proto = "https",
): Partial<Request> => ({
	get: (name: string) => {
		const lc = name.toLowerCase();
		if (lc === "dpop") return dpopHeader;
		if (lc === "host") return host;
		return undefined;
	},
	method,
	originalUrl: path,
	protocol: proto,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createDPoPMechanism", () => {
	let replayStore: ReturnType<typeof createMemoryDPoPReplayStore>;
	let mechanism: ReturnType<typeof createDPoPMechanism>;

	beforeEach(() => {
		replayStore = createMemoryDPoPReplayStore();
		mechanism = createDPoPMechanism({
			replayStore,
			iatWindowSeconds: 60,
			algWhitelist: ["ES256", "ES384", "EdDSA", "RS256"],
		});
	});

	// -------------------------------------------------------------------------
	// Step 1: DPoP header absent → null (not throw)
	// -------------------------------------------------------------------------

	it("returns null when DPoP header is absent (step 1)", async () => {
		const req = makeReq(undefined);
		const result = await mechanism.extract(req as Request);
		expect(result).toBeNull();
	});

	// -------------------------------------------------------------------------
	// Step 2: Multiple DPoP headers → throw
	// -------------------------------------------------------------------------

	it("throws when DPoP header contains a comma (multiple values, step 2)", async () => {
		const req = makeReq("token1,token2");
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(mechanism.extract(req as Request)).rejects.toMatchObject({
			reason: "multiple_headers",
		});
	});

	// -------------------------------------------------------------------------
	// Step 5: alg whitelist
	// -------------------------------------------------------------------------

	it("accepts a proof with alg=ES256 (in default whitelist, step 5)", async () => {
		const { proof } = await mintProof({ alg: "ES256" });
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
		expect(result?.kind).toBe("dpop");
	});

	it("rejects a proof with alg not in whitelist (step 5)", async () => {
		// HS256 requires a symmetric key; not in the allowlist.
		// We use RS256 mechanism but override alg in header — parseProof will
		// accept it structurally, but the verifier's whitelist check rejects it.
		// Simplest approach: use custom mechanism with restricted whitelist.
		const restrictedMechanism = createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			algWhitelist: ["ES256"],
		});
		const { proof } = await mintProof({ alg: "ES384" });
		const req = makeReq(proof);
		await expect(restrictedMechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({
				replayStore: createMemoryDPoPReplayStore(),
				algWhitelist: ["ES256"],
			}).extract(makeReq(proof) as Request),
		).rejects.toMatchObject({ reason: "alg_not_allowed" });
	});

	// -------------------------------------------------------------------------
	// Step 8: Signature verification
	// -------------------------------------------------------------------------

	it("accepts a validly signed proof (step 8)", async () => {
		const { proof } = await mintProof();
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	it("rejects a tampered proof signature (step 8)", async () => {
		const { proof } = await mintProof({ tamperSignature: true });
		const req = makeReq(proof);
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({ replayStore: createMemoryDPoPReplayStore() }).extract(
				makeReq(proof) as Request,
			),
		).rejects.toMatchObject({ reason: "signature_invalid" });
	});

	// -------------------------------------------------------------------------
	// Step 10: htm match
	// -------------------------------------------------------------------------

	it("accepts when htm matches request method (step 10)", async () => {
		const { proof } = await mintProof({ htm: "GET", htu: "https://as.example/token" });
		const req = makeReq(proof, "GET", "/token");
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	it("rejects when htm does not match request method (step 10)", async () => {
		const { proof } = await mintProof({ htm: "GET" });
		const req = makeReq(proof, "POST"); // proof says GET, request is POST
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({ replayStore: createMemoryDPoPReplayStore() }).extract(req as Request),
		).rejects.toMatchObject({ reason: "htm_mismatch" });
	});

	it("accepts htm case-insensitively (step 10)", async () => {
		const { proof } = await mintProof({ htm: "post" });
		const req = makeReq(proof, "POST");
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	// -------------------------------------------------------------------------
	// Step 11: htu match (including normalization)
	// -------------------------------------------------------------------------

	it("accepts when htu matches request URL (step 11)", async () => {
		const { proof } = await mintProof({ htu: "https://as.example/token" });
		const req = makeReq(proof, "POST", "/token", "as.example", "https");
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	it("rejects when htu does not match request URL (step 11)", async () => {
		const { proof } = await mintProof({ htu: "https://other.example/token" });
		const req = makeReq(proof, "POST", "/token", "as.example", "https");
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({ replayStore: createMemoryDPoPReplayStore() }).extract(req as Request),
		).rejects.toMatchObject({ reason: "htu_mismatch" });
	});

	it("accepts when htu matches after normalization (trailing slash difference, step 11)", async () => {
		// Proof says /token (no slash); request URL would also normalize the same.
		const { proof } = await mintProof({ htu: "HTTPS://AS.EXAMPLE/token" });
		const req = makeReq(proof, "POST", "/token", "as.example", "https");
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	it("accepts when htu has default port removed (step 11)", async () => {
		const { proof } = await mintProof({ htu: "https://as.example:443/token" });
		const req = makeReq(proof, "POST", "/token", "as.example", "https");
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	// -------------------------------------------------------------------------
	// Step 12: iat window
	// -------------------------------------------------------------------------

	it("accepts a proof with iat within the window (step 12)", async () => {
		const iat = Math.floor(Date.now() / 1000) - 30; // 30s ago, window = 60s
		const { proof } = await mintProof({ iat });
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
	});

	it("rejects a proof with iat outside the window — too old (step 12)", async () => {
		const iat = Math.floor(Date.now() / 1000) - 120; // 120s ago, window = 60s
		const { proof } = await mintProof({ iat });
		const req = makeReq(proof);
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({
				replayStore: createMemoryDPoPReplayStore(),
				iatWindowSeconds: 60,
			}).extract(req as Request),
		).rejects.toMatchObject({ reason: "iat_out_of_window" });
	});

	it("rejects a proof with iat in the future beyond window (step 12)", async () => {
		const iat = Math.floor(Date.now() / 1000) + 120; // 120s in future, window = 60s
		const { proof } = await mintProof({ iat });
		const req = makeReq(proof);
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(
			createDPoPMechanism({
				replayStore: createMemoryDPoPReplayStore(),
				iatWindowSeconds: 60,
			}).extract(req as Request),
		).rejects.toMatchObject({ reason: "iat_out_of_window" });
	});

	// -------------------------------------------------------------------------
	// Step 14: replay protection
	// -------------------------------------------------------------------------

	it("first use of a (jti, jkt) pair returns a binding (step 14)", async () => {
		const { proof, jkt } = await mintProof();
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result).not.toBeNull();
		expect(result?.confirmation).toMatchObject({ jkt });
	});

	it("second use of the same (jti, jkt) pair throws replay_detected (step 14)", async () => {
		const { proof } = await mintProof();
		const req = makeReq(proof);
		// First call succeeds.
		await mechanism.extract(req as Request);
		// Second call with the same proof should throw.
		await expect(mechanism.extract(req as Request)).rejects.toThrow(DPoPError);
		await expect(mechanism.extract(makeReq(proof) as Request)).rejects.toMatchObject({
			reason: "replay_detected",
		});
	});

	// -------------------------------------------------------------------------
	// Confirmation shape
	// -------------------------------------------------------------------------

	it("returned binding has kind='dpop' and confirmation.jkt matching proof.jkt", async () => {
		const keyPair = await generateKeyPair("ES256");
		const jwk = await exportJWK(keyPair.publicKey);
		const expectedJkt = await computeJkt(jwk);
		const { proof } = await mintProof({ keyPair });
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result?.kind).toBe("dpop");
		expect(result?.confirmation).toEqual({ jkt: expectedJkt });
	});

	it("uses proof.jkt (no redundant re-computation)", async () => {
		// This test documents the no-re-compute contract: the binding's
		// confirmation.jkt must equal the value computed from the proof's
		// JWK, which parseProof already computed.
		const { proof, jkt } = await mintProof();
		const req = makeReq(proof);
		const result = await mechanism.extract(req as Request);
		expect(result?.confirmation).toEqual({ jkt });
	});

	// -------------------------------------------------------------------------
	// kind and intentExplicit flags
	// -------------------------------------------------------------------------

	it("mechanism has kind='dpop' and intentExplicit=true", () => {
		expect(mechanism.kind).toBe("dpop");
		expect(mechanism.intentExplicit).toBe(true);
	});

	// -------------------------------------------------------------------------
	// Coverage gap follow-ups from /multi-agent-review (Sub-PR 2b round 1)
	// -------------------------------------------------------------------------

	// I-4: pin whitelist case-sensitivity. RFC 9449 §4.3 + JOSE treat `alg`
	// as case-sensitive. An operator misconfiguring HOCON with lowercase
	// (`alg-whitelist = ["es256"]`) would otherwise silently reject every
	// valid ES256 proof — or worse, a lowercased entry might be assumed
	// equivalent to an uppercased proof when it is not.
	it("whitelist comparison is case-sensitive — lowercase whitelist entry does not match uppercase alg", async () => {
		const { proof } = await mintProof({ alg: "ES256" });
		const lowerCaseMechanism = createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			algWhitelist: ["es256"], // operator typo: lowercase
		});
		await expect(lowerCaseMechanism.extract(makeReq(proof) as Request)).rejects.toMatchObject({
			reason: "alg_not_allowed",
		});
	});

	// I-5: pin that parseProof's private_jwk screen (Sub-PR 2a step 7)
	// propagates through the verifier intact. Without this regression
	// test, a refactor of the verifier's parseProof call site could
	// accidentally swallow the parser-layer error.
	it("propagates private_jwk error from parseProof (step 7 / Sub-PR 2a)", async () => {
		const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
		const pubJwk = await exportJWK(publicKey);
		const legitProof = await new SignJWT({
			htm: "POST",
			htu: "https://as.example/token",
			iat: Math.floor(Date.now() / 1000),
			jti: crypto.randomUUID(),
		})
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: pubJwk })
			.sign(privateKey);
		const [_h, payload, sig] = legitProof.split(".");
		// Surgically inject a private-key field (`d`) so the JWK passes
		// parseProof's structural shape but fails its private-field screen.
		const headerObj = {
			typ: "dpop+jwt",
			alg: "ES256",
			jwk: { ...pubJwk, d: "REDACTED" },
		};
		const fakeHeader = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
		const crafted = `${fakeHeader}.${payload}.${sig}`;
		await expect(mechanism.extract(makeReq(crafted) as Request)).rejects.toMatchObject({
			reason: "private_jwk",
			code: "invalid_dpop_proof",
		});
	});

	// I-(round-2): pin that an `htu` containing userinfo is rejected as
	// `malformed_proof` rather than being silently normalized away (RFC 9449
	// §4 — userinfo has no meaning at the token endpoint). Without this
	// guard, a proof for `https://attacker:pwn@as.example/...` would
	// equality-match the server-built `https://as.example/...` after the
	// canonical reconstruction drops the credentials.
	it("rejects htu containing userinfo as malformed_proof (RFC 9449 §4)", async () => {
		const { proof } = await mintProof({ htu: "https://attacker:pwn@as.example/token" });
		await expect(mechanism.extract(makeReq(proof) as Request)).rejects.toMatchObject({
			reason: "malformed_proof",
			code: "invalid_dpop_proof",
			message: expect.stringContaining("userinfo"),
		});
	});

	// Narrow the replay-store catch so RangeError (programming/config bug)
	// is NOT misclassified as `replay_store_unavailable` (availability
	// fault). Operator triage signal must distinguish "fix the ttl config"
	// from "check Redis health".
	it("lets RangeError from replay store propagate (programmer/config bug, not transport)", async () => {
		const rangingStore = {
			seen: async (_jti: string, _jkt: string, ttlSeconds: number) => {
				if (ttlSeconds <= 0) {
					throw new RangeError(`ttlSeconds must be positive (got ${ttlSeconds})`);
				}
				return false;
			},
		};
		const rangingMechanism = createDPoPMechanism({
			replayStore: rangingStore,
			replayTtlSeconds: -1, // forces RangeError at the store layer
		});
		const { proof } = await mintProof();
		// RangeError must surface as RangeError, NOT wrapped as DPoPError.
		await expect(rangingMechanism.extract(makeReq(proof) as Request)).rejects.toThrow(RangeError);
	});

	// I-2: pin that replay-store transport faults surface as the dedicated
	// `replay_store_unavailable` audit signal — not a raw Error that would
	// otherwise propagate up to `tokenBindingMw` and lose operator triage.
	it("wraps replay store transport errors as replay_store_unavailable (audit signal distinct from client-garbage)", async () => {
		const failingStore = {
			seen: async () => {
				throw new Error("ECONNREFUSED — Redis down");
			},
		};
		const failingMechanism = createDPoPMechanism({ replayStore: failingStore });
		const { proof } = await mintProof();
		await expect(failingMechanism.extract(makeReq(proof) as Request)).rejects.toMatchObject({
			reason: "replay_store_unavailable",
			code: "invalid_dpop_proof",
		});
	});
});

// ---------------------------------------------------------------------------
// Replay TTL vs iat window (#199 M1)
// ---------------------------------------------------------------------------

describe("replayTtlSeconds must cover the whole iat acceptance window", () => {
	/**
	 * The `iat` check is `Math.abs(now - iat) > iatWindowSeconds`, so a proof
	 * with `iat = T` is acceptable across `now ∈ [T - W, T + W]` — a span of
	 * `2W`, not `W`.
	 *
	 * A replay entry is written when the proof is FIRST seen, which under
	 * clock skew can be as early as `T - W`, and it expires at
	 * `firstSeen + TTL`. For the entry to still exist for as long as the proof
	 * is accepted, `T - W + TTL >= T + W`, i.e. `TTL >= 2W`. Below that, the
	 * proof outlives its own replay entry and becomes replayable while still
	 * inside its acceptance window.
	 */
	const capturingLogger = (warns: { obj: unknown; msg?: string }[]) =>
		({
			debug: () => {},
			info: () => {},
			warn: (obj: unknown, msg?: string) => warns.push({ obj, msg }),
			error: () => {},
			child() {
				return this;
			},
		}) as unknown as Parameters<typeof createDPoPMechanism>[0]["logger"];

	const ttlWarnings = (warns: { obj: unknown; msg?: string }[]) =>
		warns.filter((w) => (w.obj as { reason?: string })?.reason === "replay_ttl_below_iat_window");

	it("warns when replayTtlSeconds is below 2x iatWindowSeconds", () => {
		const warns: { obj: unknown; msg?: string }[] = [];
		createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			iatWindowSeconds: 180,
			// Satisfies the old "at least iatWindowSeconds" advice and is still
			// short of the 360 the window actually needs.
			replayTtlSeconds: 300,
			logger: capturingLogger(warns),
		});

		const matched = ttlWarnings(warns);
		expect(matched).toHaveLength(1);
		expect(matched[0]?.obj).toMatchObject({
			iatWindowSeconds: 180,
			replayTtlSeconds: 300,
			requiredTtlSeconds: 360,
		});
	});

	it("does not warn at exactly 2x, nor for the defaults", () => {
		const atBoundary: { obj: unknown; msg?: string }[] = [];
		createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			iatWindowSeconds: 150,
			replayTtlSeconds: 300,
			logger: capturingLogger(atBoundary),
		});
		expect(ttlWarnings(atBoundary)).toHaveLength(0);

		// Defaults are 60 / 300 — 2x60 = 120, comfortably covered.
		const defaults: { obj: unknown; msg?: string }[] = [];
		createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			logger: capturingLogger(defaults),
		});
		expect(ttlWarnings(defaults)).toHaveLength(0);
	});
});
