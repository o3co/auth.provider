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
 * The WebAuthn routes parse their own bodies, and no path beneath them.
 *
 * Core mounts each route's router on its path by prefix, and each router
 * installed its JSON parser with `router.use`, so it read the body of every
 * path beneath the route as well: a later module's
 * `/oauth/webauthn/registration/options/custom` received a body WebAuthn had
 * already consumed. Booted through `createApp`, as the composition is.
 */

import {
	createApp,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler } from "express";
import supertest from "supertest";
import { describe, expect, it } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import { webauthnModule } from "../module.mjs";

const ROUTES = [
	"/oauth/webauthn/registration/options",
	"/oauth/webauthn/registration/verify",
	"/oauth/webauthn/authentication/options",
] as const;

const webauthnConfig: WebAuthnConfig = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit: 100, windowSeconds: 60 } },
};

/**
 * A route of some other module, with no parser of its own: it reads the
 * request stream itself and reports what it found — and whether anything
 * had parsed the body before it ran.
 */
const readsItsOwnBody: RequestHandler = (req, res) => {
	const parsedBefore = (req as { body?: unknown }).body ?? null;
	if (req.readableEnded) {
		res.json({ raw: null, parsedBefore });
		return;
	}
	let raw = "";
	req.setEncoding("utf8");
	req.on("data", (chunk: string) => {
		raw += chunk;
	});
	req.on("end", () => {
		res.json({ raw, parsedBefore });
	});
};

/** A module listed after `webauthnModule`, serving a path beneath each of its routes. */
const beneathModule = defineModule({
	name: "test:beneath-the-webauthn-routes",
	contributes: {
		routes: [
			() => {
				const router = express.Router();
				for (const route of ROUTES) {
					router.post(`${route.slice("/oauth".length)}/custom`, readsItsOwnBody);
				}
				return { id: "beneath", mountPath: "/oauth", handler: router };
			},
		],
	},
});

const bootApp = async () => {
	const base = makeValidAppConfig();
	const config = {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
		deployment: { mode: "single" },
	};
	const handle = await createApp({
		modules: [
			webauthnModule,
			defineModule({
				name: "test:webauthn-body-config",
				provides: { webauthnConfig: () => webauthnConfig },
			}),
			defineModule({
				name: "test:webauthn-body-key-store",
				provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
			}),
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			memoryWebAuthnCredentialStoreModule,
			defaultChallengeCeremonyModule,
			defineModule({
				name: "test:webauthn-body-grant-policy",
				provides: {
					grantPolicy: (): GrantPolicyHook => ({
						kind: "test-noop",
						evaluate: async () => ({ outcome: "allow" }) as const,
					}),
				},
			}),
			beneathModule,
		],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

describe("the WebAuthn routes' JSON parser", () => {
	it.each(ROUTES)("leaves the body of a later module's route beneath %s unread", async (route) => {
		const { handle, app } = await bootApp();
		try {
			const res = await supertest(app)
				.post(`${route}/custom`)
				.set("Content-Type", "application/json")
				.send('{"a":1}');

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ raw: '{"a":1}', parsedBefore: null });
		} finally {
			await handle.dispose();
		}
	});

	it("still parses the route's own JSON body", async () => {
		// Malformed JSON at the route itself is refused by its parser, which is
		// how a body that was parsed shows here.
		const { handle, app } = await bootApp();
		try {
			const res = await supertest(app)
				.post(ROUTES[0])
				.set("Content-Type", "application/json")
				.send("{not json");

			expect(res.status).toBe(400);
		} finally {
			await handle.dispose();
		}
	});
});
