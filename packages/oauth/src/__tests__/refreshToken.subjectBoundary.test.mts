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
 * The refresh grant against the subject's revocation boundary, by the
 * presented token's authentication time as well as its issuance time.
 *
 * A refresh token with no `sid` (a passkey family, or one minted without a
 * user-session store) has no session for admission to read, so the boundary
 * is the one thing that ends it after a credential change. Pinned here: a
 * token whose `iat` postdates the boundary but whose `auth_time` does not is
 * `invalid_grant`, at the first read and at the reads after the policy and
 * after the rotation (which revokes the family); and a token with no
 * `auth_time` is judged by its `iat` alone.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	createInMemorySubjectRevocation,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantPolicyHook,
	type RefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRotation,
	type SubjectRevocation,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const CLIENT_ID = "client1";
const SUBJECT = "u1";
const config = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { refresh_token: { enabled: true } },
	},
} as unknown as AppConfig;

const INVALID_REFRESH_TOKEN = {
	status: 400,
	error: "invalid_grant",
	errorDescription: "invalid refresh_token",
};

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/**
 * A sessionless refresh token, as the passkey grant mints one: a family and
 * a jti, no `sid`. `authTime` absent leaves `auth_time` out.
 */
const refreshToken = (opts: { iat: number; authTime?: number }): Promise<string> =>
	new SignJWT({
		sub: SUBJECT,
		scope: "read",
		amr: ["hwk"],
		family_id: "fam-1",
		jti: "jti-1",
		...(opts.authTime === undefined ? {} : { auth_time: opts.authTime }),
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuedAt(opts.iat)
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

const makeGrant = (opts: {
	subjectRevocation: SubjectRevocation;
	grantPolicy?: GrantPolicyHook;
	family?: {
		readonly rotation: RefreshTokenFamilyRotation;
		readonly revocation: RefreshTokenFamilyRevocation;
	};
}) => {
	const rotate = vi.fn(
		opts.family?.rotation.rotate ?? (async () => ({ outcome: "rotated" as const })),
	);
	const handler = createRefreshTokenGrant({
		...grantSettingsFrom(config),
		keyStore: createSymmetricKeyStore(SECRET),
		refreshTokenFamilyRotation: { register: vi.fn(async () => {}), rotate },
		refreshTokenFamilyRevocation:
			opts.family?.revocation ?? ({ revokeFamily: vi.fn(async () => {}) } as never),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
		sessionRequirementResolver: resolverForTests([], {
			issuer: "https://issuer.test",
			actions: OAUTH_ADMISSION_ACTIONS,
		}),
		subjectRevocation: opts.subjectRevocation,
	});
	return { handler, rotate };
};

const ctx = (token: string): GrantContext => ({
	body: { refresh_token: token },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
});

/** A boundary stamped `agoSeconds` before now, as a credential change in the past leaves it. */
const stampedAgo = async (agoSeconds: number) => {
	const revocation = createInMemorySubjectRevocation();
	const stampMs = Date.now() - agoSeconds * 1000;
	await revocation.revokeBefore(SUBJECT, new Date(stampMs), new Date(Date.now() + 3_600_000));
	return { revocation, stampSeconds: Math.floor(stampMs / 1000) };
};

const revokeNow = (revocation: SubjectRevocation) =>
	revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));

describe("the refresh grant — a sessionless token's authentication time against the subject boundary", () => {
	it("refuses a token issued after the boundary from an authentication before it", async () => {
		const { revocation, stampSeconds } = await stampedAgo(60);
		const { handler, rotate } = makeGrant({ subjectRevocation: revocation });

		const { result } = await handler.handle(
			ctx(await refreshToken({ iat: nowSeconds(), authTime: stampSeconds - 30 })),
		);

		expect(result).toEqual(INVALID_REFRESH_TOKEN);
		expect(rotate).not.toHaveBeenCalled();
	});

	it("refreshes a token whose authentication is past the boundary and its allowance", async () => {
		const { revocation, stampSeconds } = await stampedAgo(60);
		const { handler, rotate } = makeGrant({ subjectRevocation: revocation });

		const { result } = await handler.handle(
			ctx(await refreshToken({ iat: nowSeconds(), authTime: stampSeconds + 5 })),
		);

		expect(result.status).toBe(200);
		expect(rotate).toHaveBeenCalledTimes(1);
	});

	it("refuses one when the subject is revoked while the policy evaluates, before anything rotates", async () => {
		// `iat` a few seconds ahead of this clock, within the verifier's
		// allowance, so only `auth_time` is at or before the stamp.
		const revocation = createInMemorySubjectRevocation();
		const policy: GrantPolicyHook = {
			kind: "slow",
			evaluate: async () => {
				await revokeNow(revocation);
				return { outcome: "allow" };
			},
		};
		const { handler, rotate } = makeGrant({ subjectRevocation: revocation, grantPolicy: policy });
		const token = await refreshToken({ iat: nowSeconds() + 10, authTime: nowSeconds() - 60 });

		const { result } = await handler.handle(ctx(token));

		expect(result).toEqual(INVALID_REFRESH_TOKEN);
		expect(rotate).not.toHaveBeenCalled();
		// The same token is refused at its next use.
		expect(
			(await makeGrant({ subjectRevocation: revocation }).handler.handle(ctx(token))).result,
		).toEqual(INVALID_REFRESH_TOKEN);
	});

	it("refuses one when the subject is revoked during the rotation, and revokes the family", async () => {
		const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		const familyRevocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		await rotation.register("jti-1", "fam-1", Date.now() + 86_400_000);
		const revocation = createInMemorySubjectRevocation();
		const { handler } = makeGrant({
			subjectRevocation: revocation,
			family: {
				rotation: {
					register: rotation.register,
					rotate: async (...args) => {
						const outcome = await rotation.rotate(...args);
						await revokeNow(revocation);
						return outcome;
					},
				},
				revocation: familyRevocation,
			},
		});

		const { result } = await handler.handle(
			ctx(await refreshToken({ iat: nowSeconds() + 10, authTime: nowSeconds() - 60 })),
		);

		expect(result).toEqual(INVALID_REFRESH_TOKEN);
		expect(await familyRevocation.isFamilyRevoked("fam-1")).toBe(true);
	});

	describe("a token with no auth_time is judged by its iat alone", () => {
		it("refreshes one issued after the boundary and its allowance", async () => {
			const { revocation } = await stampedAgo(60);
			const { handler } = makeGrant({ subjectRevocation: revocation });

			const { result } = await handler.handle(ctx(await refreshToken({ iat: nowSeconds() })));

			expect(result.status).toBe(200);
		});

		it("refuses one issued at or before the boundary", async () => {
			const { revocation, stampSeconds } = await stampedAgo(60);
			const { handler } = makeGrant({ subjectRevocation: revocation });

			const { result } = await handler.handle(ctx(await refreshToken({ iat: stampSeconds - 30 })));

			expect(result).toEqual(INVALID_REFRESH_TOKEN);
		});
	});
});
