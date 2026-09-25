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
 * `full-pki` under `on-unavailable = "reject"`, when a revocation source
 * cannot answer — through core's real dispatchers, the real mechanism, and
 * CRL distribution points on real loopback sockets.
 *
 * A source that could not be reached or did not deliver a usable answer (a
 * refused connection, a timeout, an HTTP error, an answer that is not DER, a
 * stale list) is the server's outage, not a verdict on the client's
 * certificate: the mechanism refuses with `unavailable`, the dispatcher
 * answers `503 temporarily_unavailable` and writes the outage's one line at
 * error, and nothing else logs it. It used to be `400 invalid_certificate`,
 * which a client reads as "your certificate is bad". A certificate the list
 * names is still a verdict, and so is one whose revocation cannot be checked
 * for a reason of its own (a distribution point outside the allowlist).
 * Under `"allow"` nothing changes.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { type Logger, protectedResourceBindingMw, tokenBindingMw } from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createMtlsMechanism } from "#/extractor.mjs";
import { computeCertThumbprint } from "#/thumbprint.mjs";
import type { Minted } from "./pkiFactory.mjs";
import {
	basicConstraints,
	clientAuthEku,
	crlDistributionPoints,
	distributionPoint,
	distributionPointsExtension,
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
	ocspAia,
} from "./pkiFactory.mjs";

const FRAMES = expect.stringMatching(/^ {4}at /);

/** A logger that records what each level is handed. */
function recordingLogger(): { logger: Logger; calls: Array<{ level: string; args: unknown[] }> } {
	const calls: Array<{ level: string; args: unknown[] }> = [];
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
		};
	const logger: Logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	return { logger, calls };
}

const servers: Server[] = [];

afterEach(async () => {
	await Promise.all(
		servers.splice(0).map(
			(server) =>
				new Promise<void>((resolve) => {
					// A server that never answers still holds its sockets open.
					server.closeAllConnections();
					server.close(() => resolve());
				}),
		),
	);
});

const listen = async (
	handle: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<string> => {
	const server = createServer(handle);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	servers.push(server);
	return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

/** A loopback origin nothing listens on. */
const closedOrigin = async (): Promise<string> => {
	const server = createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return `http://127.0.0.1:${port}`;
};

type LeafCrl = "refused" | "hanging" | "garbage" | "clean" | "revoked";

/**
 * root → intermediate → leaf. The intermediate's CRL (the root's list) is
 * served clean from a live loopback server; the leaf's (the intermediate's
 * list) is `leafCrl`: a refused connection, bytes that are not DER, a clean
 * list, or one naming the leaf. With `leafResponderRefused`, the leaf also
 * names an OCSP responder nothing listens on — for `revocation.mode = "both"`.
 * `extra.leafCn` names the leaf; `extra.morePoints` adds distribution points
 * after the first — one the live server answers 404 (`missing`) or one on a
 * port nothing listens on (`refused`). `extra.intSourcesRefused` points the
 * intermediate's own CRL and OCSP responder at ports nothing listens on.
 */
const pki = async (
	leafCrl: LeafCrl,
	leafPointHost = "127.0.0.1",
	leafResponderRefused = false,
	extra: {
		readonly leafCn?: string;
		readonly morePoints?: readonly ("missing" | "refused")[];
		readonly intSourcesRefused?: boolean;
	} = {},
) => {
	const root = await mintCa("Root", 1);
	const lists: Record<string, Uint8Array> = {};
	const live = await listen((req, res) => {
		const body = lists[req.url ?? ""];
		res.writeHead(body === undefined ? 404 : 200, { "content-type": "application/pkix-crl" });
		res.end(body === undefined ? undefined : Buffer.from(body));
	});
	const intPoint = extra.intSourcesRefused
		? `${await closedOrigin()}/root.crl`
		: `${live}/root.crl`;
	const intResponder = extra.intSourcesRefused ? `${await closedOrigin()}/ocsp` : undefined;
	const int = await mintIntermediate("Intermediate", 2, root, {
		extensions: [
			basicConstraints(true),
			keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
			crlDistributionPoints([intPoint]),
			...(intResponder !== undefined ? [ocspAia(intResponder)] : []),
		],
	});
	const leafPoint =
		leafCrl === "refused"
			? `${await closedOrigin()}/int.crl`
			: leafCrl === "hanging"
				? // Accepts the connection and never answers.
					`${await listen(() => {})}/int.crl`
				: `${live.replace("127.0.0.1", leafPointHost)}/int.crl`;
	const morePoints: string[] = [];
	for (const [index, kind] of (extra.morePoints ?? []).entries()) {
		morePoints.push(
			kind === "missing"
				? `${live}/int-missing-${index}.crl`
				: `${await closedOrigin()}/int-${index}.crl`,
		);
	}
	const leafResponder = leafResponderRefused ? `${await closedOrigin()}/ocsp` : undefined;
	const leaf = await mintLeaf(extra.leafCn ?? "client", 10, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			// One distribution point per URL: separate points, not alternatives.
			distributionPointsExtension([leafPoint, ...morePoints].map((url) => distributionPoint(url))),
			...(leafResponder !== undefined ? [ocspAia(leafResponder)] : []),
		],
	});
	lists["/root.crl"] = await mintCrl({ issuer: root });
	if (leafCrl === "garbage") lists["/int.crl"] = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
	if (leafCrl === "clean") lists["/int.crl"] = await mintCrl({ issuer: int });
	if (leafCrl === "revoked") lists["/int.crl"] = await mintCrl({ issuer: int, revoked: [leaf] });
	return { root, int, leaf, leafPoint, morePoints, leafResponder, intPoint, intResponder };
};

const mechanism = (
	root: Minted,
	onUnavailable: "reject" | "allow",
	logger: Logger,
	mode: "crl" | "both" = "crl",
	fetchTimeoutMs = 2_000,
) =>
	createMtlsMechanism({
		source: "header",
		certHeaderDialect: "envoy",
		trustedProxies: ["loopback"],
		mode: "full-pki",
		trustedCas: [root.pem],
		fullPki: {
			revocation: {
				mode,
				"on-unavailable": onUnavailable,
				"allowed-hosts": ["127.0.0.1"],
				"fetch-timeout-ms": fetchTimeoutMs,
				"cache-ttl-seconds": 60,
				"max-response-bytes": 65_536,
			},
		},
		logger,
	});

const xfcc = (leaf: Minted, int: Minted): string =>
	`Cert=${encodeURIComponent(leaf.pem)};Chain=${encodeURIComponent(int.pem)}`;

/** `/oauth/token` behind core's token-binding dispatcher, and `/resource` behind the protected-resource one. */
const appWith = (
	root: Minted,
	onUnavailable: "reject" | "allow",
	mode: "crl" | "both" = "crl",
	fetchTimeoutMs = 2_000,
) => {
	const { logger, calls } = recordingLogger();
	const mechanisms = [mechanism(root, onUnavailable, logger, mode, fetchTimeoutMs)];
	const app = express();
	app.post(
		"/oauth/token",
		tokenBindingMw({ mechanisms, dispatchPolicy: "intent-explicit", logger }),
		(req, res) => {
			res.status(200).json({ binding: req.tokenBinding ?? null });
		},
	);
	app.get("/resource", protectedResourceBindingMw({ mechanisms, logger }), (_req, res) => {
		res.status(200).json({ ok: true });
	});
	return { app, calls };
};

const escaped = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * One source that could not be used, as the outage line projects it: an
 * error of its own, so the cap on a projected message cuts no other source,
 * naming the certificate it was asked about last — `null` for a subject long
 * enough that the cap cuts it.
 */
const sourceMember = (
	source: "crl" | "ocsp",
	url: string,
	reason: string,
	cause?: unknown,
	subject: string | null = "CN=client",
) => ({
	name: "MtlsRevocationSourceError",
	detail:
		subject === null
			? expect.stringContaining(`${source} ${url}: ${reason} — `)
			: expect.stringMatching(
					new RegExp(`^${escaped(`${source} ${url}: ${reason} — `)}.+; for ${escaped(subject)}$`),
				),
	reason,
	stack: FRAMES,
	...(cause === undefined ? {} : { cause }),
});

/**
 * The dispatcher's one outage line: the certificate named last in a short
 * message, and one member per source that could not be used.
 */
const outageLine = (event: string, members: readonly unknown[], subject = "CN=client") => [
	{
		mechanism: "mtls",
		code: "temporarily_unavailable",
		reason: "revocation_unavailable",
		err: {
			name: "MtlsRevocationUnavailableError",
			detail: `revocation status could not be determined for ${subject}`,
			stack: FRAMES,
			aggregateErrors: members,
		},
	},
	event,
];

const REFUSED = expect.objectContaining({
	name: "TypeError",
	cause: expect.objectContaining({ code: "ECONNREFUSED" }),
});

describe("full-pki, on-unavailable = reject: a revocation source that cannot answer is an outage", () => {
	it("a refused connection: 503 temporarily_unavailable, one error line, nothing at warn", async () => {
		const { root, int, leaf, leafPoint } = await pki("refused");
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine("token_binding_unavailable", [
					sourceMember("crl", leafPoint, "fetch_failed", REFUSED),
				]),
			},
		]);
		const line = calls[0]?.args[0] as { err: { aggregateErrors: Array<{ detail: string }> } };
		expect(line.err.aggregateErrors[0]?.detail).toContain("network_error (ECONNREFUSED)");
	});

	it("a point that accepts the connection and never answers: timed out, the same 503", async () => {
		const { root, int, leaf, leafPoint } = await pki("hanging");
		const { app, calls } = appWith(root, "reject", "crl", 300);

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine("token_binding_unavailable", [
					sourceMember("crl", leafPoint, "fetch_failed"),
				]),
			},
		]);
		const line = calls[0]?.args[0] as { err: { aggregateErrors: Array<{ detail: string }> } };
		expect(line.err.aggregateErrors[0]?.detail).toContain("timeout (300ms)");
	});

	it("an answer that is not DER: the same, pkijs's error inside", async () => {
		const { root, int, leaf, leafPoint } = await pki("garbage");
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine("token_binding_unavailable", [
					sourceMember(
						"crl",
						leafPoint,
						"unparseable",
						expect.objectContaining({ name: "AsnError" }),
					),
				]),
			},
		]);
	});

	it("at a protected resource: 503, no challenge, one protected_resource_binding_unavailable line", async () => {
		const { root, int, leaf, leafPoint } = await pki("refused");
		const { app, calls } = appWith(root, "reject");
		const token = await new SignJWT({
			sub: "u1",
			cnf: { "x5t#S256": computeCertThumbprint(leaf.der) },
		})
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.sign(new Uint8Array(32));

		const res = await request(app)
			.get("/resource")
			.set("authorization", `Bearer ${token}`)
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine("protected_resource_binding_unavailable", [
					sourceMember("crl", leafPoint, "fetch_failed", REFUSED),
				]),
			},
		]);
	});
});

describe("full-pki, on-unavailable = reject: what stays a verdict", () => {
	it("a certificate its CRL lists: 400 invalid_certificate, logged at warn, nothing at error", async () => {
		const { root, int, leaf } = await pki("revoked");
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");
		expect(calls.filter(({ level }) => level === "error")).toEqual([]);
		expect(calls.map(({ args }) => args[1])).toEqual([
			"mtls_full_pki_validation_failed",
			"token_binding_proof_invalid",
		]);
	});

	it("a distribution point outside the allowlist: the certificate's own shape, 400 as before", async () => {
		const { root, int, leaf } = await pki("clean", "localhost");
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");
		expect(calls.filter(({ level }) => level === "error")).toEqual([]);
		expect(calls.map(({ args }) => args[1])).toEqual([
			"mtls_revocation_unavailable_rejected",
			"mtls_full_pki_validation_failed",
			"token_binding_proof_invalid",
		]);
	});
});

describe("full-pki, on-unavailable = allow: unchanged", () => {
	it("a refused connection: the certificate is bound, one allowed line at warn", async () => {
		const { root, int, leaf } = await pki("refused");
		const { app, calls } = appWith(root, "allow");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(200);
		expect(res.body.binding).toMatchObject({ kind: "mtls" });
		expect(calls.map(({ level, args }) => [level, args[1]])).toEqual([
			["warn", "mtls_revocation_unavailable_allowed"],
		]);
	});
});

describe("revocation.mode = both: the OCSP fallback is logged once it has answered, and only then", () => {
	it("OCSP down, the CRL answers: the certificate is bound, the fallback's one warn and nothing else", async () => {
		const { root, int, leaf } = await pki("clean", "127.0.0.1", true);
		const { app, calls } = appWith(root, "reject", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(200);
		expect(res.body.binding).toMatchObject({ kind: "mtls" });
		expect(calls.map(({ level, args }) => [level, args[1]])).toEqual([
			["warn", "mtls_revocation_ocsp_fallback"],
		]);
		expect(calls[0]?.args[0]).toMatchObject({
			subject: "CN=client",
			reason: "fetch_failed",
			err: expect.objectContaining({ name: "TypeError" }),
		});
	});

	it("both down under reject: 503, the dispatcher's one error line, naming both sources and carrying both errors", async () => {
		const { root, int, leaf, leafPoint, leafResponder } = await pki("refused", "127.0.0.1", true);
		const { app, calls } = appWith(root, "reject", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls.map(({ level, args }) => [level, args[1]])).toEqual([
			["error", "token_binding_unavailable"],
		]);
		expect(calls[0]?.args).toEqual(
			outageLine("token_binding_unavailable", [
				sourceMember("ocsp", leafResponder as string, "fetch_failed", REFUSED),
				sourceMember("crl", leafPoint, "fetch_failed", REFUSED),
			]),
		);
	});

	it("OCSP down and one of two CRL points down under reject: one error line, naming OCSP and the point", async () => {
		// The CRL answered from its first point, but the second could not be
		// used: under "reject" a partial answer is no answer, so the fallback
		// was not served — no fallback line, and OCSP is named on the one line
		// the dispatcher writes.
		const { root, int, leaf, morePoints, leafResponder } = await pki("clean", "127.0.0.1", true, {
			morePoints: ["missing"],
		});
		const { app, calls } = appWith(root, "reject", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine("token_binding_unavailable", [
					sourceMember("ocsp", leafResponder as string, "fetch_failed", REFUSED),
					sourceMember("crl", morePoints[0] as string, "fetch_failed"),
				]),
			},
		]);
	});

	it("both down under allow: the certificate is bound, one allowed line naming both sources", async () => {
		const { root, int, leaf } = await pki("refused", "127.0.0.1", true);
		const { app, calls } = appWith(root, "allow", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(200);
		expect(calls.map(({ level, args }) => [level, args[1]])).toEqual([
			["warn", "mtls_revocation_unavailable_allowed"],
		]);
		expect(calls[0]?.args[0]).toMatchObject({
			detail: expect.stringMatching(/ocsp: fetch_failed .*; crl: fetch_failed /),
		});
	});
});

describe("the outage line's account survives a long subject", () => {
	it("each source that could not be used is its own member, so a long DN pushes no URL off the line", async () => {
		// loggableError caps a message at 256 characters. One message holding
		// the subject and every URL lost the URLs behind a long DN; one short
		// member per source keeps each within its own cap.
		const leafCn = `client-${"x".repeat(230)}`;
		const { root, int, leaf, leafPoint, morePoints } = await pki("refused", "127.0.0.1", false, {
			leafCn,
			morePoints: ["refused"],
		});
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		const line = calls[0]?.args[0] as {
			err: { detail: string; aggregateErrors: Array<{ detail: string }> };
		};
		expect(calls).toHaveLength(1);
		expect(line.err.aggregateErrors).toEqual([
			sourceMember("crl", leafPoint, "fetch_failed", REFUSED, null),
			sourceMember("crl", morePoints[0] as string, "fetch_failed", REFUSED, null),
		]);
		expect(
			line.err.detail.startsWith("revocation status could not be determined for CN=client-x"),
		).toBe(true);
	});
});

describe("one outage line for the whole path", () => {
	it("the leaf served on the CRL and the intermediate down under both: 503, the one error line, naming the leaf's responder too", async () => {
		// A shared OCSP outage with the root's CRL down: the leaf's CRL answers,
		// the intermediate's does not. The request is refused, so no line may
		// say it was served on the fallback — and the responder the leaf could
		// not reach is part of the outage the one line accounts for.
		const { root, int, leaf, leafResponder, intPoint, intResponder } = await pki(
			"clean",
			"127.0.0.1",
			true,
			{ intSourcesRefused: true },
		);
		const { app, calls } = appWith(root, "reject", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine(
					"token_binding_unavailable",
					[
						sourceMember("ocsp", leafResponder as string, "fetch_failed", REFUSED),
						sourceMember(
							"ocsp",
							intResponder as string,
							"fetch_failed",
							REFUSED,
							"CN=Intermediate",
						),
						sourceMember("crl", intPoint, "fetch_failed", REFUSED, "CN=Intermediate"),
					],
					"CN=Intermediate",
				),
			},
		]);
	});

	it("the leaf and the intermediate both down: one line with every certificate's sources, each naming its certificate", async () => {
		// An operator who fixes the first source must not find the next one
		// only after the first is back.
		const { root, int, leaf, leafPoint, intPoint } = await pki("refused", "127.0.0.1", false, {
			intSourcesRefused: true,
		});
		const { app, calls } = appWith(root, "reject");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(503);
		expect(calls).toEqual([
			{
				level: "error",
				args: outageLine(
					"token_binding_unavailable",
					[
						sourceMember("crl", leafPoint, "fetch_failed", REFUSED),
						sourceMember("crl", intPoint, "fetch_failed", REFUSED, "CN=Intermediate"),
					],
					"CN=client; CN=Intermediate",
				),
			},
		]);
	});

	it("the leaf's OCSP down and its CRL listing it: 400, the verdict's lines, no fallback line", async () => {
		// The fallback line marks a request served on the CRL. This one was
		// refused, and the verdict's own lines are its account.
		const { root, int, leaf } = await pki("revoked", "127.0.0.1", true);
		const { app, calls } = appWith(root, "reject", "both");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc(leaf, int));

		expect(res.status).toBe(400);
		expect(calls.map(({ level, args }) => [level, args[1]])).toEqual([
			["warn", "mtls_full_pki_validation_failed"],
			["warn", "token_binding_proof_invalid"],
		]);
	});
});
