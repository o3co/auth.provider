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
 * What reaches the log when the token endpoint refuses a certificate header,
 * through the real composition: `mtlsModule` booted by core's `createApp`,
 * core's token-binding dispatcher answering the refusal.
 *
 * The extractor states the refusal — an `MtlsError` with its `reason` and,
 * when a parser refused the material, that parser's error as `cause` — and
 * the dispatcher's one verdict line, `token_binding_proof_invalid`, carries
 * the `reason` and the refusal's projection (its `cause` projected inside
 * it). Before, the line carried the mechanism and the code alone, so what
 * was wrong with the header reached no log at all.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BootstrapMap, createApp, defineModule, type Logger } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { mtlsModule } from "#/module.mjs";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");

/** A logged projection's `stack`: frames only. */
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

const tokenRoute = defineModule({
	name: "token-route",
	requires: [],
	optional: [],
	contributes: {
		routes: [
			() => {
				const router = Router();
				router.post("/token", (_req, res) => {
					res.status(200).json({ ok: true });
				});
				return { id: "test-token", mountPath: "/oauth", handler: router };
			},
		],
	},
});

const boot = async (dialect: "envoy" | "plain-pem") => {
	const { logger, calls } = recordingLogger();
	const bootstrap = {
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				mtls: {
					enabled: true,
					source: "header",
					"cert-header": "x-forwarded-client-cert",
					"cert-header-dialect": dialect,
					mode: "self-signed",
					"trusted-cas": [],
					// supertest dials the listener over loopback.
					"trusted-proxies": ["loopback"],
				},
				tokenBinding: { "dispatch-policy": "intent-explicit" },
			},
		} as never,
		pathResolver: (s: string) => s,
		logger,
	} satisfies Record<string, unknown> as BootstrapMap;
	const handle = await createApp({
		modules: [mtlsModule, tokenRoute],
		bootstrapComponents: bootstrap,
	});
	const app = express();
	app.use(handle.router);
	return { app, handle, calls };
};

/** The one verdict line the dispatcher wrote, and nothing at error. */
const verdictLine = (calls: Array<{ level: string; args: unknown[] }>) => {
	const lines = calls.filter(({ args }) => args[1] === "token_binding_proof_invalid");
	expect(lines).toHaveLength(1);
	expect(lines[0]?.level).toBe("warn");
	expect(calls.filter(({ level }) => level === "error")).toEqual([]);
	return lines[0]?.args[0] as Record<string, unknown>;
};

describe("a refused certificate header at the token endpoint", () => {
	it("an XFCC value the envoy parser refuses: reason malformed_header, the parser's error inside the projection", async () => {
		const { app, handle, calls } = await boot("envoy");
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", "By=spiffe://example;NoCertField=here")
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");
		expect(verdictLine(calls)).toEqual({
			mechanism: "mtls",
			code: "invalid_certificate",
			reason: "malformed_header",
			err: {
				name: "MtlsError",
				detail: "envoy header parse failure",
				code: "invalid_certificate",
				reason: "malformed_header",
				stack: FRAMES,
				cause: { name: "Error", detail: expect.stringContaining("Cert="), stack: FRAMES },
			},
		});
		await handle.dispose();
	});

	it("a PEM block whose DER is not a certificate: reason cert_decode_failed, OpenSSL's error inside the projection", async () => {
		const { app, handle, calls } = await boot("plain-pem");
		const notACertificate = `-----BEGIN CERTIFICATE-----\n${Buffer.from("not a certificate").toString("base64")}\n-----END CERTIFICATE-----\n`;
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(notACertificate))
			.send({});

		expect(res.status).toBe(400);
		expect(verdictLine(calls)).toMatchObject({
			mechanism: "mtls",
			code: "invalid_certificate",
			reason: "cert_decode_failed",
			err: {
				name: "MtlsError",
				detail: "DER parse failed",
				reason: "cert_decode_failed",
				cause: { name: "Error", code: expect.any(String) },
			},
		});
		await handle.dispose();
	});

	it("an accepted certificate writes no verdict line", async () => {
		const { app, handle, calls } = await boot("plain-pem");
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});
		expect(res.status).toBe(200);
		expect(calls.filter(({ args }) => args[1] === "token_binding_proof_invalid")).toEqual([]);
		await handle.dispose();
	});
});
