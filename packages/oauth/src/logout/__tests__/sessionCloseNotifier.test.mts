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
 * The session-close notifier oauth contributes: one back-channel logout
 * token per notice, to the relying party's registered URI, settled or
 * rejected by what the delivery answers.
 */

import {
	ClientEntrySchema,
	type ClientRepository,
	createSymmetricKeyStore,
	InMemoryClientRepository,
	type SessionCloseNotice,
} from "@o3co/auth-provider-core";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createSessionCloseNotifier } from "#/logout/sessionCloseNotifier.mjs";

const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxx");
const ISSUER = "https://auth.test";
const BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout";

const clients: Record<string, Record<string, unknown>> = {
	rp: { clientId: "rp", backchannelLogoutUri: "https://rp.example/bc" },
	"rp-no-sid": {
		clientId: "rp-no-sid",
		backchannelLogoutUri: "https://rp-no-sid.example/bc",
		backchannelLogoutSessionRequired: false,
	},
	"rp-no-uri": { clientId: "rp-no-uri" },
};

const clientRepository = {
	findById: async (clientId: string) => clients[clientId] ?? null,
} as unknown as ClientRepository;

const notice = (overrides: Partial<SessionCloseNotice> = {}): SessionCloseNotice => ({
	sid: "sid-1",
	sub: "user-1",
	clientId: "rp",
	cause: "rp_logout",
	...overrides,
});

/** A fetch that answers `status`, recording each call. */
const answering = (status: number) =>
	vi.fn(async (_url: string, _init: RequestInit) => new Response(null, { status }));

const notifierWith = (fetchImpl: unknown, repository: ClientRepository = clientRepository) =>
	createSessionCloseNotifier({
		clientRepository: repository,
		keyStore,
		issuer: ISSUER,
		fetchImpl: fetchImpl as typeof fetch,
	});

/** The logout token one call posted. */
const tokenOf = (call: [string, RequestInit] | undefined): string => {
	const token = new URLSearchParams(String(call?.[1].body)).get("logout_token");
	if (token === null) throw new Error("no logout_token was posted");
	return token;
};

describe("createSessionCloseNotifier", () => {
	it("posts one logout token for the session to the relying party's back-channel URI", async () => {
		const fetchImpl = answering(200);
		await expect(notifierWith(fetchImpl).notify(notice())).resolves.toBeUndefined();
		expect(fetchImpl).toHaveBeenCalledTimes(1);
		const call = fetchImpl.mock.calls[0] as [string, RequestInit];
		expect(call[0]).toBe("https://rp.example/bc");
		expect(call[1].method).toBe("POST");
		expect((call[1].headers as Record<string, string>)["Content-Type"]).toBe(
			"application/x-www-form-urlencoded",
		);
		const token = tokenOf(call);
		expect(decodeProtectedHeader(token).typ).toBe("logout+jwt");
		const claims = decodeJwt(token);
		expect(claims).toMatchObject({ iss: ISSUER, aud: "rp", sub: "user-1", sid: "sid-1" });
		expect(claims.events).toEqual({ [BCL_EVENT]: {} });
		expect(claims.nonce).toBeUndefined();
	});

	it("settles, posting nothing, for a relying party with no back-channel URI", async () => {
		const fetchImpl = answering(200);
		await expect(
			notifierWith(fetchImpl).notify(notice({ clientId: "rp-no-uri" })),
		).resolves.toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("settles, posting nothing, for a client that is no longer registered", async () => {
		const fetchImpl = answering(200);
		await expect(
			notifierWith(fetchImpl).notify(notice({ clientId: "gone" })),
		).resolves.toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it.each([400, 401, 403, 404, 410])("settles on a permanent refusal (%i)", async (status) => {
		await expect(notifierWith(answering(status)).notify(notice())).resolves.toBeUndefined();
	});

	it.each([408, 429, 500, 502, 503])("rejects on an answer worth retrying (%i)", async (status) => {
		await expect(notifierWith(answering(status)).notify(notice())).rejects.toThrow(String(status));
	});

	it("rejects when the relying party cannot be reached", async () => {
		const fetchImpl = vi.fn(async () => {
			throw new TypeError("fetch failed");
		});
		await expect(notifierWith(fetchImpl).notify(notice())).rejects.toThrow();
	});

	it("rejects when the client registry cannot answer", async () => {
		const failing = {
			findById: async () => {
				throw new Error("client store down");
			},
		} as unknown as ClientRepository;
		const fetchImpl = answering(200);
		await expect(notifierWith(fetchImpl, failing).notify(notice())).rejects.toThrow(
			"client store down",
		);
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("rejects when no logout token can be signed", async () => {
		const notifier = createSessionCloseNotifier({
			clientRepository,
			keyStore: {
				...keyStore,
				sign: async () => {
					throw new Error("key store down");
				},
			},
			issuer: ISSUER,
			fetchImpl: answering(200) as unknown as typeof fetch,
		});
		await expect(notifier.notify(notice())).rejects.toThrow("key store down");
	});

	describe("the sid, by one rule for every cause", () => {
		/** A registry holding `rp`, registered through the client boundary's own defaults. */
		const registered = (extra: Record<string, unknown> = {}) =>
			new InMemoryClientRepository(
				new Map([
					[
						"rp",
						ClientEntrySchema.parse({
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "rp-secret-long-enough",
							allowedGrantTypes: ["authorization_code"],
							allowedRedirectUris: ["https://rp.example/cb"],
							allowedScopes: ["openid"],
							backchannelLogoutUri: "https://rp.example/bc",
							...extra,
						}),
					],
				]),
			);

		it.each(["rp_logout", "subject_revocation"] as const)(
			"%s carries the sid for a relying party registered with the default",
			async (cause) => {
				const fetchImpl = answering(200);
				await notifierWith(fetchImpl, registered()).notify(notice({ cause }));
				const claims = decodeJwt(tokenOf(fetchImpl.mock.calls[0] as [string, RequestInit]));
				expect(claims).toMatchObject({ sub: "user-1", sid: "sid-1" });
			},
		);

		it.each(["rp_logout", "subject_revocation"] as const)(
			"%s leaves the sid out for a relying party that declined it",
			async (cause) => {
				const fetchImpl = answering(200);
				await notifierWith(
					fetchImpl,
					registered({ backchannelLogoutSessionRequired: false }),
				).notify(notice({ cause }));
				const claims = decodeJwt(tokenOf(fetchImpl.mock.calls[0] as [string, RequestInit]));
				expect(claims.sid).toBeUndefined();
				expect(claims.sub).toBe("user-1");
			},
		);
	});

	it("cancels the answer's body, which it never reads", async () => {
		let cancelled = false;
		const body = new ReadableStream({
			cancel() {
				cancelled = true;
			},
		});
		const fetchImpl = vi.fn(async () => new Response(body, { status: 200 }));
		await notifierWith(fetchImpl).notify(notice());
		await Promise.resolve();
		expect(cancelled).toBe(true);
	});

	it("leaves the sid out of a session's token where the relying party declined it", async () => {
		const fetchImpl = answering(200);
		await notifierWith(fetchImpl).notify(notice({ clientId: "rp-no-sid" }));
		const claims = decodeJwt(tokenOf(fetchImpl.mock.calls[0] as [string, RequestInit]));
		expect(claims.sid).toBeUndefined();
		expect(claims.sub).toBe("user-1");
	});
});
