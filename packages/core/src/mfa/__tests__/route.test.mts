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
