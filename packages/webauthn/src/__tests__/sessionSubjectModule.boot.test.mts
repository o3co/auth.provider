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
 * `webauthnSessionSubjectModule` through `createApp` (the session-admission
 * ADR's D8): its route mounts between the session middleware and the two
 * registration routes, and a composition missing either side of that order
 * — `webauthnModule`, or the module contributing `session-middleware` — is
 * refused at boot as `route-order-target-missing`, naming the target, rather
 * than booting a bridge that runs in the wrong place or not at all.
 */

import {
	BootError,
	createApp,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Module,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type { WebAuthnConfig } from "#/config.mjs";
import { webauthnModule } from "#/module.mjs";
import { webauthnSessionSubjectModule } from "#/sessionSubject.mjs";
import { makeAppConfig } from "./appConfig.fixture.mjs";

const base = makeAppConfig();
const bootstrapComponents = {
	config: {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
	},
	pathResolver: (p: string) => p,
} as never;

const webauthnConfig: WebAuthnConfig = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
};

/** What `webauthnModule` needs beside itself. */
const webauthnSupport: readonly Module[] = [
	defineModule({
		name: "test:webauthn-config",
		provides: { webauthnConfig: () => webauthnConfig },
	}),
	defineModule({
		name: "test:key-store",
		provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
	}),
	defineModule({
		name: "test:grant-policy",
		provides: {
			grantPolicy: (): GrantPolicyHook => ({
				kind: "test",
				evaluate: async () => ({ outcome: "allow" }) as const,
			}),
		},
	}),
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	defaultChallengeCeremonyModule,
	memoryWebAuthnCredentialStoreModule,
];

/** The user-session store the module requires. */
const userSessionStoreModule = defineModule({
	name: "test:user-session-store",
	provides: {
		userSessionStore: () =>
			({
				kind: "test",
				create: async () => {},
				get: async () => null,
				delete: async () => {},
			}) as unknown as UserSessionStore,
	},
});

/** A stand-in for the session package's session-store module: the route it contributes. */
const sessionMiddlewareModule = defineModule({
	name: "test:session-middleware",
	contributes: {
		routes: [
			() => ({
				id: "session-middleware",
				mountPath: "/",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			}),
		],
	},
});

const subjectModule = webauthnSessionSubjectModule({
	subjectFor: (session) => ({ userId: session.sub }),
});

const refusal = async (modules: readonly Module[]): Promise<unknown> =>
	createApp({ modules: [...modules], bootstrapComponents }).then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);

describe("webauthnSessionSubjectModule — composed", () => {
	it("mounts its route after the session middleware and before both registration routes", async () => {
		const handle = await createApp({
			modules: [
				sessionMiddlewareModule,
				webauthnModule,
				...webauthnSupport,
				userSessionStoreModule,
				subjectModule,
			],
			bootstrapComponents,
		});
		try {
			const ids = handle.routes.map((r) => r.contribution.id);
			const at = (id: string) => ids.indexOf(id);
			expect(at("webauthn-session-subject")).toBeGreaterThan(at("session-middleware"));
			expect(at("webauthn-session-subject")).toBeLessThan(at("webauthn-registration-options"));
			expect(at("webauthn-session-subject")).toBeLessThan(at("webauthn-registration-verify"));
		} finally {
			await handle.dispose();
		}
	});

	it("is refused at boot without webauthnModule: route-order-target-missing, naming the registration route", async () => {
		const err = await refusal([sessionMiddlewareModule, userSessionStoreModule, subjectModule]);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "route-order-target-missing",
			details: {
				referencedBy: "webauthn-session-subject",
				direction: "before",
				id: expect.stringMatching(/^webauthn-registration-(options|verify)$/),
			},
		});
	});

	it("is refused at boot without the session middleware: route-order-target-missing, naming session-middleware", async () => {
		const err = await refusal([
			webauthnModule,
			...webauthnSupport,
			userSessionStoreModule,
			subjectModule,
		]);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "route-order-target-missing",
			details: {
				referencedBy: "webauthn-session-subject",
				direction: "after",
				id: "session-middleware",
			},
		});
	});

	it("is refused at boot without a user-session store, naming the slot", async () => {
		const err = await refusal([
			sessionMiddlewareModule,
			webauthnModule,
			...webauthnSupport,
			subjectModule,
		]);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "missing-required-component",
			details: { missingKey: "userSessionStore" },
		});
	});
});
