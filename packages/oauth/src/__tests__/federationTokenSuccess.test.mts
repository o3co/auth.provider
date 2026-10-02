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
 * The success answer's own guard: whatever stage hands it a token, one with no
 * usable access token is never answered `200`. The route's stages judge
 * usability before they get here, so this is reached only by a stage's bug.
 */

import type { AuditSink, FederationTokens } from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	createStoreUnavailableLog,
	type FederationTokenContext,
	type FederationTokenRouterOptions,
} from "#/routes/federationTokenContext.mjs";
import { isDisclosable } from "#/routes/federationTokenDisclosure.mjs";
import { answerToken } from "#/routes/federationTokenSuccess.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const answered = async (accessToken: string) => {
	const logger = createMockLogger();
	const auditSink = { kind: "mock", record: vi.fn().mockResolvedValue(undefined) } as AuditSink & {
		record: ReturnType<typeof vi.fn>;
	};
	const token: Pick<FederationTokens, "accessToken" | "expiresAt" | "scope" | "tokenType"> = {
		accessToken,
		expiresAt: null,
		scope: "openid",
		tokenType: "Bearer",
	};
	const app = express();
	app.post("/token", async (req, res) => {
		if (!isDisclosable(token)) throw new Error("a Bearer token is disclosable");
		const ctx: FederationTokenContext = {
			opts: { auditSink } as unknown as FederationTokenRouterOptions,
			req,
			res,
			name: "google",
			federation: "google",
			logger,
			storeUnavailable: createStoreUnavailableLog(logger),
			refreshBufferMs: 30_000,
			maxTokenLifetimeMs: 86_400_000,
		};
		await answerToken(
			ctx,
			{ familyId: "fam-1", sid: "sid-1", azp: "client-1", sub: "u-1" },
			token,
			false,
		);
	});
	const res = await request(app).post("/token").send();
	return { res, logger, auditSink };
};

describe("answerToken", () => {
	it("answers a token with no usable access token as no record, never 200, and audits no success", async () => {
		const { res, logger, auditSink } = await answered("");

		expect(res.status).toBe(404);
		expect(res.body).toEqual({
			error: "federation_not_linked",
			error_description: "federation 'google' tokens not found",
		});
		expect(auditSink.record).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			{ federation: "google" },
			"federation_token_record_unusable",
		);
	});

	it("answers a usable one 200 and audits the success", async () => {
		const { res, auditSink } = await answered("upstream-at");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({
			access_token: "upstream-at",
			token_type: "Bearer",
			scope: "openid",
		});
		expect(auditSink.record).toHaveBeenCalledWith(
			expect.objectContaining({
				type: "federation.token.success",
				details: { federation: "google", refreshed: false },
			}),
		);
	});
});
