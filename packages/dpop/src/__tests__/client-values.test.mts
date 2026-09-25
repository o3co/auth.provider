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
 * A DPoP proof's `typ` and `alg` are the client's to write, and a refusal of
 * them must not carry them: through core's real token-binding dispatcher,
 * whose verdict line projects the whole refusal, neither the refusal's
 * message nor any log line holds the value the client sent.
 *
 * The messages used to quote it (`expected typ=dpop+jwt, got <typ>`,
 * `alg <alg> is not in the allowlist`), and `dpop_alg_not_allowed` logged the
 * alg as sent. The alg is logged only when it is a registered JWS algorithm
 * name — a closed vocabulary that says which algorithm was refused — and as
 * `unregistered` otherwise.
 */

import { createMemoryReplaySeenSet, type Logger, tokenBindingMw } from "@o3co/auth-provider-core";
import express from "express";
import { exportJWK, generateKeyPair } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createDPoPMechanism } from "#/verifier.mjs";

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

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

/** A proof with the header given, unsigned: both refusals come before the signature is checked. */
const proof = (header: Record<string, unknown>): string =>
	`${b64(header)}.${b64({
		htm: "POST",
		htu: "https://as.example/oauth/token",
		iat: Math.floor(Date.now() / 1000),
		jti: "jti-1",
	})}.AAAA`;

const appWith = () => {
	const { logger, calls } = recordingLogger();
	const mechanism = createDPoPMechanism({
		issuer: "https://as.example",
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
	});
	const app = express();
	app.post(
		"/oauth/token",
		tokenBindingMw({ mechanisms: [mechanism], dispatchPolicy: "intent-explicit", logger }),
		(_req, res) => {
			res.status(200).json({ ok: true });
		},
	);
	return { app, calls };
};

const publicJwk = async () => {
	const { publicKey } = await generateKeyPair("ES256");
	return exportJWK(publicKey);
};

/** The dispatcher's verdict line. */
const verdictOf = (calls: Array<{ level: string; args: unknown[] }>) =>
	calls.find(({ args }) => args[1] === "token_binding_proof_invalid")?.args[0] as {
		reason: string;
		err: { detail: string };
	};

describe("a DPoP refusal of the client's own typ or alg quotes neither", () => {
	it("a typ other than dpop+jwt", async () => {
		const marker = "typ-marker-7f3a";
		const { app, calls } = appWith();

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof({ alg: "ES256", typ: marker, jwk: await publicJwk() }));

		expect(res.status).toBe(400);
		expect(JSON.stringify(res.body)).not.toContain(marker);
		expect(verdictOf(calls)).toMatchObject({
			reason: "typ_mismatch",
			err: { detail: "typ is not dpop+jwt" },
		});
		expect(JSON.stringify(calls)).not.toContain(marker);
	});

	it("an alg outside every registry", async () => {
		const marker = "alg-marker-9c1d";
		const { app, calls } = appWith();

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof({ alg: marker, typ: "dpop+jwt", jwk: await publicJwk() }));

		expect(res.status).toBe(400);
		expect(JSON.stringify(res.body)).not.toContain(marker);
		expect(verdictOf(calls)).toMatchObject({
			reason: "alg_not_allowed",
			err: { detail: "alg is not an accepted DPoP algorithm" },
		});
		expect(calls).toContainEqual({
			level: "warn",
			args: [
				{ alg: "unregistered", whitelist: ["ES256", "ES384", "EdDSA", "RS256"] },
				"dpop_alg_not_allowed",
			],
		});
		expect(JSON.stringify(calls)).not.toContain(marker);
	});

	it("a registered alg the deployment does not accept is still named on dpop_alg_not_allowed", async () => {
		const { app, calls } = appWith();

		await request(app)
			.post("/oauth/token")
			.set("DPoP", proof({ alg: "PS512", typ: "dpop+jwt", jwk: await publicJwk() }));

		expect(calls).toContainEqual({
			level: "warn",
			args: [
				{ alg: "PS512", whitelist: ["ES256", "ES384", "EdDSA", "RS256"] },
				"dpop_alg_not_allowed",
			],
		});
		expect(verdictOf(calls)?.err.detail).toBe("alg is not an accepted DPoP algorithm");
	});
});
