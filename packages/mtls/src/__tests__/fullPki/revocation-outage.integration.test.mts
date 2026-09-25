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
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
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
		servers
			.splice(0)
			.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
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

type LeafCrl = "refused" | "garbage" | "clean" | "revoked";

/**
 * root → intermediate → leaf. The intermediate's CRL (the root's list) is
 * served clean from a live loopback server; the leaf's (the intermediate's
 * list) is `leafCrl`: a refused connection, bytes that are not DER, a clean
 * list, or one naming the leaf.
 */
const pki = async (leafCrl: LeafCrl, leafPointHost = "127.0.0.1") => {
	const root = await mintCa("Root", 1);
	const lists: Record<string, Uint8Array> = {};
	const live = await listen((req, res) => {
		const body = lists[req.url ?? ""];
		res.writeHead(body === undefined ? 404 : 200, { "content-type": "application/pkix-crl" });
		res.end(body === undefined ? undefined : Buffer.from(body));
	});
	const int = await mintIntermediate("Intermediate", 2, root, {
		extensions: [
			basicConstraints(true),
			keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
			crlDistributionPoints([`${live}/root.crl`]),
		],
	});
	const leafPoint =
		leafCrl === "refused"
			? `${await closedOrigin()}/int.crl`
			: `${live.replace("127.0.0.1", leafPointHost)}/int.crl`;
	const leaf = await mintLeaf("client", 10, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			crlDistributionPoints([leafPoint]),
		],
	});
	lists["/root.crl"] = await mintCrl({ issuer: root });
	if (leafCrl === "garbage") lists["/int.crl"] = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
	if (leafCrl === "clean") lists["/int.crl"] = await mintCrl({ issuer: int });
	if (leafCrl === "revoked") lists["/int.crl"] = await mintCrl({ issuer: int, revoked: [leaf] });
	return { root, int, leaf, leafPoint };
};

const mechanism = (root: Minted, onUnavailable: "reject" | "allow", logger: Logger) =>
	createMtlsMechanism({
		source: "header",
		certHeaderDialect: "envoy",
		trustedProxies: ["loopback"],
		mode: "full-pki",
		trustedCas: [root.pem],
		fullPki: {
			revocation: {
				mode: "crl",
				"on-unavailable": onUnavailable,
				"allowed-hosts": ["127.0.0.1"],
				"fetch-timeout-ms": 2_000,
				"cache-ttl-seconds": 60,
				"max-response-bytes": 65_536,
			},
		},
		logger,
	});

const xfcc = (leaf: Minted, int: Minted): string =>
	`Cert=${encodeURIComponent(leaf.pem)};Chain=${encodeURIComponent(int.pem)}`;

/** `/oauth/token` behind core's token-binding dispatcher, and `/resource` behind the protected-resource one. */
const appWith = (root: Minted, onUnavailable: "reject" | "allow") => {
	const { logger, calls } = recordingLogger();
	const mechanisms = [mechanism(root, onUnavailable, logger)];
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

const outageLine = (event: string, leafPoint: string, cause: unknown) => [
	{
		mechanism: "mtls",
		code: "temporarily_unavailable",
		reason: "revocation_unavailable",
		err: {
			name: "MtlsRevocationUnavailableError",
			detail: expect.stringContaining(leafPoint),
			stack: FRAMES,
			...(cause === undefined ? {} : { cause }),
		},
	},
	event,
];

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
				args: outageLine(
					"token_binding_unavailable",
					leafPoint,
					expect.objectContaining({
						name: "TypeError",
						cause: expect.objectContaining({ code: "ECONNREFUSED" }),
					}),
				),
			},
		]);
		const line = calls[0]?.args[0] as { err: { detail: string } };
		expect(line.err.detail).toContain("network_error (ECONNREFUSED)");
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
				args: outageLine(
					"token_binding_unavailable",
					leafPoint,
					expect.objectContaining({ name: "AsnError" }),
				),
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
				args: outageLine(
					"protected_resource_binding_unavailable",
					leafPoint,
					expect.objectContaining({ name: "TypeError" }),
				),
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
