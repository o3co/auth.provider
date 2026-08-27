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
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Request } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MtlsError } from "#/errors.mjs";
import { createMtlsMechanism } from "#/extractor.mjs";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");
const INTERMEDIATE_PEM = readFileSync(join(fixturesDir, "intermediate.pem"), "utf8");
const ROOT_PEM = readFileSync(join(fixturesDir, "root.pem"), "utf8");
const LEAF_DER = new X509Certificate(LEAF_PEM).raw;

/**
 * Pre-computed expected thumbprint for the leaf cert. Computed by
 * `computeCertThumbprint(LEAF_DER)`; pinning prevents the extractor's
 * thumbprint emission from silently drifting.
 */
import { createHash } from "node:crypto";

const EXPECTED_LEAF_THUMBPRINT = createHash("sha256")
	.update(LEAF_DER)
	.digest("base64url")
	.replace(/=+$/, "");

/** The peer address every header-source test connects from unless it says otherwise. */
const TRUSTED_PEER = "10.0.0.7";

/**
 * Build a minimal Express-like Request stub.
 *
 * `socket.remoteAddress` is part of the minimum since #280: the header source
 * authenticates the forwarding proxy by its TCP peer address, so a stub
 * without one is not a request the mechanism can accept.
 */
const makeReq = (
	headers: Record<string, string | undefined>,
	remoteAddress: string | undefined = TRUSTED_PEER,
): Partial<Request> => ({
	get: (name: string) => headers[name.toLowerCase()],
	socket: { remoteAddress } as unknown as Request["socket"],
});

/**
 * tls-layer source needs `req.socket.getPeerCertificate()`. Build a stub
 * that mirrors Node's `getPeerCertificate()` return shape (`{ raw: Buffer }`)
 * — the extractor uses `raw` and ignores the rest.
 */
const makeReqWithTlsCert = (rawDer: Uint8Array | null): Partial<Request> => ({
	get: () => undefined,
	socket: {
		getPeerCertificate: () => (rawDer ? { raw: Buffer.from(rawDer) } : {}),
	} as unknown as Request["socket"],
});

describe("createMtlsMechanism — header source", () => {
	it("returns null when the configured header is absent (ambient mechanism)", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeader: "x-forwarded-client-cert",
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const result = await mech.extract(makeReq({}) as Request);
		expect(result).toBeNull();
	});

	it("kind === 'mtls' and intentExplicit === false (ambient transport-layer signal)", () => {
		// Per spec §3.2: mTLS is the ambient mechanism — even when sourced from
		// a forwarded header, the underlying signal is transport-layer cert
		// presentation. Dispatch policy ("intent-explicit") relies on this flag.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		expect(mech.kind).toBe("mtls");
		expect(mech.intentExplicit).toBe(false);
	});

	it("extracts thumbprint from a plain-pem dialect header", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeader: "x-forwarded-client-cert",
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }) as Request);
		expect(result).not.toBeNull();
		expect(result?.kind).toBe("mtls");
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("extracts thumbprint from an envoy dialect XFCC header (URL-encoded Cert=)", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeader: "x-forwarded-client-cert",
			certHeaderDialect: "envoy",
			mode: "self-signed",
		});
		const xfcc = `By=spiffe://cluster/sa/svc;Hash=abc;Cert=${encodeURIComponent(LEAF_PEM)}`;
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request);
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("throws MtlsError(malformed_header) when the envoy XFCC lacks Cert=", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": "By=foo;Hash=bar" }) as Request),
		).rejects.toMatchObject({ reason: "malformed_header" });
	});

	it("throws MtlsError(cert_decode_failed) when the PEM body is unparseable", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		await expect(
			mech.extract(
				makeReq({
					"x-forwarded-client-cert":
						"-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----",
				}) as Request,
			),
		).rejects.toMatchObject({ reason: "cert_decode_failed" });
	});

	it("uses 'x-forwarded-client-cert' as the default header name", async () => {
		// certHeader is optional; default per spec §10.1 + §10.2 schema default.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }) as Request);
		expect(result?.kind).toBe("mtls");
	});

	it("uses 'envoy' as the default dialect", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			mode: "self-signed",
		});
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)}`;
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request);
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});
});

describe("createMtlsMechanism — tls-layer source", () => {
	it("returns null when getPeerCertificate returns an empty object (no client cert)", async () => {
		const mech = createMtlsMechanism({ source: "tls-layer", mode: "self-signed" });
		const result = await mech.extract(makeReqWithTlsCert(null) as Request);
		expect(result).toBeNull();
	});

	it("extracts thumbprint from req.socket.getPeerCertificate().raw", async () => {
		const mech = createMtlsMechanism({ source: "tls-layer", mode: "self-signed" });
		const result = await mech.extract(makeReqWithTlsCert(LEAF_DER) as Request);
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("throws MtlsError(tls_peer_unavailable) when req.socket lacks getPeerCertificate", async () => {
		const mech = createMtlsMechanism({ source: "tls-layer", mode: "self-signed" });
		const req = { socket: {} } as unknown as Request;
		await expect(mech.extract(req)).rejects.toMatchObject({ reason: "tls_peer_unavailable" });
	});
});

describe("createMtlsMechanism — validity window (mode-agnostic)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("self-signed mode rejects a cert that is not yet valid (now < notBefore)", async () => {
		// The committed leaf.pem was minted on 2026-05-19; pivot now to 1990
		// so notBefore is in the future. extractor.mts §6.4 must reject with
		// reason `cert_not_yet_valid`.
		vi.setSystemTime(new Date("1990-01-01T00:00:00Z"));
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }) as Request),
		).rejects.toMatchObject({ reason: "cert_not_yet_valid" });
	});

	it("self-signed mode rejects a cert that has expired (now > notAfter)", async () => {
		// Leaf is 1-year valid from generation date (~2026-05-19), so pivot
		// to 2126 puts now well past notAfter.
		vi.setSystemTime(new Date("2126-01-01T00:00:00Z"));
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }) as Request),
		).rejects.toMatchObject({ reason: "cert_expired" });
	});

	it("PKI mode also runs the validity window check before chain walk", async () => {
		// PKI mode shares step §6.4 — an expired leaf is rejected with the
		// validity reason, not chain_validation_failed.
		vi.setSystemTime(new Date("2126-01-01T00:00:00Z"));
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [ROOT_PEM],
		});
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(INTERMEDIATE_PEM)}`;
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request),
		).rejects.toMatchObject({ reason: "cert_expired" });
	});
});

describe("createMtlsMechanism — PKI mode (chain validation before thumbprint)", () => {
	it("PKI mode rejects a chain when trusted-cas don't include the root (chain_validation_failed)", async () => {
		// Provide a 'wrong' trust anchor (the leaf itself, which won't validate
		// the intermediate). PKI mode must fail chain validation, not silently
		// emit a thumbprint.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [LEAF_PEM], // intentionally wrong
		});
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(INTERMEDIATE_PEM)}`;
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request),
		).rejects.toMatchObject({ reason: "chain_validation_failed" });
	});

	it("PKI mode accepts a chain when trusted-cas contains the root (XFCC chain extracted)", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [ROOT_PEM],
		});
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(INTERMEDIATE_PEM)}`;
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request);
		expect(result?.kind).toBe("mtls");
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("PKI mode self-signed leaf with no intermediates rejected (no path to anchor)", async () => {
		// A leaf with no Chain= and a trusted-cas that doesn't include its issuer
		// → "no path to trust anchor" → chain_validation_failed.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "pki",
			trustedCas: [ROOT_PEM],
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }) as Request),
		).rejects.toMatchObject({ reason: "chain_validation_failed" });
	});
});

// ---------------------------------------------------------------------------
// #280 — the certificate must come from the TLS layer, or from an
// authenticated trusted proxy (RFC 8705 §3).
// ---------------------------------------------------------------------------

describe("createMtlsMechanism — default certificate source (#280)", () => {
	it("defaults to the TLS layer when `source` is omitted", async () => {
		// The pre-#280 default was "header", which trusted a forwarded header
		// from any peer that could reach the process. The certificate now comes
		// from the transport by default; a forwarded header is opt-in.
		const mech = createMtlsMechanism({ mode: "self-signed" });
		const result = await mech.extract(makeReqWithTlsCert(LEAF_DER) as Request);
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("ignores a forwarded cert header entirely under the default source", async () => {
		// A request carrying a forged header but no TLS-layer certificate is an
		// unbound request, not an mTLS one. It must not throw either — the
		// header is simply not this mechanism's input.
		const mech = createMtlsMechanism({ mode: "self-signed" });
		const req = {
			get: (name: string) =>
				name.toLowerCase() === "x-forwarded-client-cert" ? LEAF_PEM : undefined,
			socket: { getPeerCertificate: () => ({}) } as unknown as Request["socket"],
		} as Request;
		expect(await mech.extract(req)).toBeNull();
	});
});

describe("createMtlsMechanism — trusted-proxy allowlist for the header source (#280)", () => {
	it("throws at construction when source === 'header' and no trustedProxies are configured", () => {
		expect(() =>
			createMtlsMechanism({
				source: "header",
				certHeaderDialect: "plain-pem",
				mode: "self-signed",
			}),
		).toThrow(/trustedProxies/i);
	});

	it("throws at construction when source === 'header' and trustedProxies is empty", () => {
		expect(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [],
				certHeaderDialect: "plain-pem",
				mode: "self-signed",
			}),
		).toThrow(/trustedProxies/i);
	});

	it("accepts the forwarded certificate when the peer is an allowlisted proxy", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const result = await mech.extract(
			makeReq({ "x-forwarded-client-cert": LEAF_PEM }, "10.0.0.7") as Request,
		);
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("rejects a forwarded certificate from a peer that is not an allowlisted proxy", async () => {
		// The threat #280 closes: anyone who can open a connection to the app
		// could previously assert any client identity by setting this header.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }, "203.0.113.9") as Request),
		).rejects.toMatchObject({ reason: "untrusted_proxy" });
	});

	it("rejects rather than ignoring — a forged header must not silently downgrade to unbound", async () => {
		// CONTRIBUTING.md §4: `extract` returns null only for ABSENCE. Present
		// but unauthenticated material is invalid, and invalid material rejects
		// the whole request instead of falling through to whatever else
		// validates. Returning null here would let an attacker strip a binding
		// off someone else's request by injecting a header.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["loopback"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }, "198.51.100.4") as Request),
		).rejects.toBeInstanceOf(MtlsError);
	});

	it("returns null when an untrusted peer sends no certificate header at all", async () => {
		// Absence stays absence regardless of who is connecting — an ordinary
		// unbound request from a direct client must not become an error.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		expect(await mech.extract(makeReq({}, "203.0.113.9") as Request)).toBeNull();
	});

	it("rejects when the peer address is unavailable", async () => {
		// `remoteAddress` is undefined on a destroyed socket and on a
		// Unix-domain listener. Neither can be proven to be the proxy.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const req = {
			get: (name: string) =>
				name.toLowerCase() === "x-forwarded-client-cert" ? LEAF_PEM : undefined,
			socket: {} as unknown as Request["socket"],
		} as Request;
		await expect(mech.extract(req)).rejects.toMatchObject({ reason: "untrusted_proxy" });
	});

	it("checks the socket peer, never the X-Forwarded-For-derived req.ip", async () => {
		// `req.ip` is attacker-controlled whenever Express `trust proxy` is on.
		// A request whose `ip` claims to be the proxy but whose socket peer is
		// not must still be rejected.
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const req = {
			get: (name: string) =>
				name.toLowerCase() === "x-forwarded-client-cert" ? LEAF_PEM : undefined,
			ip: "10.0.0.7",
			socket: { remoteAddress: "203.0.113.9" } as unknown as Request["socket"],
		} as Request;
		await expect(mech.extract(req)).rejects.toMatchObject({ reason: "untrusted_proxy" });
	});

	it("logs the rejection with the observed peer so the misconfiguration is diagnosable", async () => {
		const warn = vi.fn();
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: ["10.0.0.7"],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
			logger: { warn } as never,
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": LEAF_PEM }, "203.0.113.9") as Request),
		).rejects.toThrow();
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ remoteAddress: "203.0.113.9" }),
			"mtls_untrusted_proxy_rejected",
		);
	});

	it("propagates an invalid trustedProxies entry as a boot failure", () => {
		expect(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: ["proxy.internal"],
				mode: "self-signed",
			}),
		).toThrow(/not a valid IP address/i);
	});
});

describe("createMtlsMechanism — boot-time validation", () => {
	it("throws on construction when mode === 'pki' and trustedCas is empty", () => {
		// Defense-in-depth — mtlsModule's boot check is the primary
		// fail-loud path; the factory enforces the same invariant for
		// programmatic callers who bypass the module manifest.
		expect(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [TRUSTED_PEER],
				mode: "pki",
				// trustedCas omitted (defaults to undefined → effectively empty)
			}),
		).toThrow(/trustedCas/i);
	});

	it("throws on construction when mode === 'pki' and source === 'tls-layer'", () => {
		// Codex Round 1 Important #1 fix — Phase 3 narrow PKI mode requires
		// the intermediate chain (XFCC Chain=). TLS-layer full-chain
		// extraction is deferred to a future phase. Reject at construction.
		expect(() =>
			createMtlsMechanism({
				source: "tls-layer",
				mode: "pki",
				trustedCas: [ROOT_PEM],
			}),
		).toThrow(/tls-layer/i);
	});

	it("self-signed mode + empty trustedCas is allowed (trustedCas is unused)", () => {
		// `mode = "self-signed"` skips chain validation entirely, so an empty
		// (or missing) `trustedCas` is not an error.
		expect(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [TRUSTED_PEER],
				mode: "self-signed",
			}),
		).not.toThrow();
	});

	it("resolves `file:<path>` trustedCas entries from disk at boot (spec §7.1)", async () => {
		// Operator-friendly form documented in reference.conf — file paths are
		// read synchronously at module construction. Use the committed root.pem
		// fixture as the source.
		const fileRef = `file:${join(fixturesDir, "root.pem")}`;
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [fileRef],
		});
		// If the file was loaded successfully, PKI mode now has a usable trust
		// anchor and the well-formed chain should validate end-to-end.
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(INTERMEDIATE_PEM)}`;
		const result = await mech.extract(makeReq({ "x-forwarded-client-cert": xfcc }) as Request);
		expect(result?.kind).toBe("mtls");
		expect(result?.confirmation).toEqual({ "x5t#S256": EXPECTED_LEAF_THUMBPRINT });
	});

	it("throws at construction when `file:<path>` cannot be read", () => {
		expect(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [TRUSTED_PEER],
				mode: "pki",
				trustedCas: ["file:/nonexistent/path/to/ca.pem"],
			}),
		).toThrow(/failed to read file/);
	});
});

describe("MtlsError exposure", () => {
	it("thrown errors are instances of MtlsError (so callers can narrow with instanceof)", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "self-signed",
		});
		await expect(
			mech.extract(makeReq({ "x-forwarded-client-cert": "By=foo;NoCertField" }) as Request),
		).rejects.toBeInstanceOf(MtlsError);
	});
});
