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

import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createMfaProviderFactory } from "#/mfa/factory.mjs";
import { createMfaRouter } from "#/mfa/route.mjs";
import { createInMemoryTransactionStore, createTestMfaProvider } from "./fixtures.mjs";

describe("/auth/mfa/verify", () => {
	it("dispatches to providerKind from MfaPendingTransaction and resumes authorize flow on success", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () =>
			createTestMfaProvider({
				kind: "totp",
				onVerify: async (_id, proof) => ({
					success: (proof as { code?: string }).code === "111111",
				}),
			}),
		);
		const store = createInMemoryTransactionStore();
		await store.save({
			transactionId: "tx-1",
			flow: "authorize",
			subject: "user-1",
			providerKind: "totp",
			challengeId: "ch-1",
			expiresAt: new Date(Date.now() + 60_000),
			resumeState: {
				flow: "authorize",
				clientId: "client-1",
				redirectUri: "https://app.example/cb",
				responseType: "code",
			},
		});

		const onAuthorizeResume = vi.fn(async (_req, res, resume) => {
			res
				.status(200)
				.json({ resumed: "authorize", subject: resume.subject, clientId: resume.clientId });
		});

		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: store,
				onAuthorizeResume,
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);

		const res = await request(app)
			.post("/auth/mfa/verify")
			.send({ transaction_id: "tx-1", proof: { code: "111111" } });
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ resumed: "authorize", subject: "user-1", clientId: "client-1" });
		expect(onAuthorizeResume).toHaveBeenCalledTimes(1);
		expect(await store.load("tx-1")).toBeNull();
	});

	it("rejects invalid proof with 401 and does not delete transaction (retry allowed)", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () =>
			createTestMfaProvider({
				kind: "totp",
				onVerify: async () => ({ success: false, failureReason: "invalid" }),
			}),
		);
		const store = createInMemoryTransactionStore();
		await store.save({
			transactionId: "tx-retry",
			flow: "login",
			subject: "user-x",
			providerKind: "totp",
			challengeId: "ch-x",
			expiresAt: new Date(Date.now() + 60_000),
			resumeState: { flow: "login" },
		});

		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: store,
				onAuthorizeResume: async () => {},
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);

		const res = await request(app)
			.post("/auth/mfa/verify")
			.send({ transaction_id: "tx-retry", proof: { code: "wrong" } });
		expect(res.status).toBe(401);
		expect(await store.load("tx-retry")).not.toBeNull();
	});

	it("rejects expired transaction even when store returns it (S-3)", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () =>
			createTestMfaProvider({
				kind: "totp",
				onVerify: async () => ({ success: true }),
			}),
		);
		// Store that does NOT filter expired — core must enforce expiry itself.
		const expiredTx = {
			transactionId: "tx-expired",
			flow: "login" as const,
			subject: "user-z",
			providerKind: "totp",
			challengeId: "ch-z",
			expiresAt: new Date(Date.now() - 60_000),
			resumeState: { flow: "login" as const },
		};
		const deleteSpy = vi.fn(async () => {});
		const unfilteringStore = {
			async save() {},
			async load() {
				return expiredTx;
			},
			delete: deleteSpy,
		};

		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: unfilteringStore,
				onAuthorizeResume: async () => {},
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);

		const res = await request(app)
			.post("/auth/mfa/verify")
			.send({ transaction_id: "tx-expired", proof: { code: "any" } });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
		// Expired tx is deleted to prevent future accidental replay
		expect(deleteSpy).toHaveBeenCalledWith("tx-expired");
	});

	it("returns controlled 500 + deletes tx when provider.verify throws (CP-7)", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () =>
			createTestMfaProvider({
				kind: "totp",
				onVerify: async () => {
					throw new Error("backend down");
				},
			}),
		);
		const store = createInMemoryTransactionStore();
		await store.save({
			transactionId: "tx-boom",
			flow: "login",
			subject: "user-q",
			providerKind: "totp",
			challengeId: "ch-q",
			expiresAt: new Date(Date.now() + 60_000),
			resumeState: { flow: "login" },
		});

		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: store,
				onAuthorizeResume: async () => {},
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);

		const res = await request(app)
			.post("/auth/mfa/verify")
			.send({ transaction_id: "tx-boom", proof: { code: "any" } });

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
		// Transaction is deleted — cannot retry against a broken provider
		expect(await store.load("tx-boom")).toBeNull();
	});

	it("returns controlled 500 + deletes tx when providerFactory.create throws (CP-7)", async () => {
		const factory = createMfaProviderFactory();
		// No provider registered for "totp" → factory.create throws
		const store = createInMemoryTransactionStore();
		await store.save({
			transactionId: "tx-noprov",
			flow: "login",
			subject: "user-q",
			providerKind: "totp",
			challengeId: "ch-q",
			expiresAt: new Date(Date.now() + 60_000),
			resumeState: { flow: "login" },
		});

		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: store,
				onAuthorizeResume: async () => {},
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);

		const res = await request(app)
			.post("/auth/mfa/verify")
			.send({ transaction_id: "tx-noprov", proof: { code: "any" } });

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
		expect(await store.load("tx-noprov")).toBeNull();
	});

	it("returns invalid_grant for unknown/expired transaction", async () => {
		const factory = createMfaProviderFactory();
		const store = createInMemoryTransactionStore();
		const app = express();
		app.use(express.json());
		app.use(
			createMfaRouter(express as unknown as { Router: () => express.Router }, {
				providerFactory: factory,
				transactionStore: store,
				onAuthorizeResume: async () => {},
				onFederationResume: async () => {},
				onLoginResume: async () => {},
			}),
		);
		const res = await request(app).post("/auth/mfa/verify").send({ transaction_id: "nope" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
	});
});
