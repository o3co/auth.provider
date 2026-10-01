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
 * The callback's one redirect, shared by the login and the link: the
 * federation's redirect policy resolves the start's `redirectTo`; a provider
 * with no policy is a composition fault (`500`, `federation_misconfigured`);
 * a policy's refusal is answered in its words, held to RFC 6749's characters.
 */

import type { FederationProvider, Logger } from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { FederationRedirectPolicy } from "#/federations/redirect-policy.mjs";
import {
	answerNoRedirectPolicy,
	redirectAfterCallback,
} from "#/routes/FederationCallbackRedirect.mjs";

const provider = { name: "test" } as FederationProvider;

function spyLogger() {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	return logger;
}

/** An app whose one route answers through the helper, with `redirectTo` as the start kept it. */
function appFor(
	policies: ReadonlyMap<string, FederationRedirectPolicy>,
	redirectTo: string | undefined,
	logger: ReturnType<typeof spyLogger>,
) {
	const app = express();
	app.get("/callback", (_req, res) => {
		redirectAfterCallback(
			{ federationRedirectPolicyResolver: policies },
			provider,
			redirectTo,
			res,
			logger as unknown as Logger,
		);
	});
	return app;
}

const refusing = (status: number, error: string, errorDescription: string) =>
	({
		validateRedirect: () => ({ ok: true as const, value: undefined }),
		resolveCallbackRedirect: () => ({ ok: false as const, status, error, errorDescription }),
	}) as FederationRedirectPolicy;

describe("redirectAfterCallback", () => {
	it("redirects to what the provider's policy resolves for the start's redirectTo", async () => {
		const resolveCallbackRedirect = vi.fn((s: { readonly redirectTo?: string }) => ({
			ok: true as const,
			value: `https://app.example.com/done?to=${s.redirectTo ?? ""}`,
		}));
		const logger = spyLogger();
		const policy = {
			validateRedirect: () => ({ ok: true as const, value: undefined }),
			resolveCallbackRedirect,
		} as FederationRedirectPolicy;

		const res = await request(appFor(new Map([["test", policy]]), "/dash", logger)).get(
			"/callback",
		);

		expect(res.status).toBe(302);
		expect(res.headers.location).toBe("https://app.example.com/done?to=/dash");
		expect(resolveCallbackRedirect).toHaveBeenCalledTimes(1);
		expect(resolveCallbackRedirect).toHaveBeenCalledWith({ redirectTo: "/dash" });
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});

	it("answers 500 and logs one federation_misconfigured line when the provider has no policy", async () => {
		const logger = spyLogger();

		const res = await request(appFor(new Map(), "/dash", logger)).get("/callback");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			error: "internal_error",
			error_description: "redirect policy not registered for provider",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ reason: "no_redirect_policy" },
			"federation_misconfigured",
		);
		for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});

	it("answers a policy's refusal with its status and words, held to RFC 6749's characters", async () => {
		const logger = spyLogger();
		const policies = new Map([
			["test", refusing(400, "invalid_redirect", 'cible "interdite" — voir §3')],
		]);

		const res = await request(appFor(policies, "/dash", logger)).get("/callback");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_redirect",
			error_description: "cible ?interdite? ? voir ?3",
		});
		expect(res.headers.location).toBeUndefined();
	});

	it("relays a policy's server fault and logs it once at error level", async () => {
		const logger = spyLogger();
		const policies = new Map([
			["test", refusing(503, "temporarily_unavailable", "policy store down")],
		]);

		const res = await request(appFor(policies, "/dash", logger)).get("/callback");

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "policy store down",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "policy store down",
			},
			"redirect_policy_server_fault",
		);
		for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});

	it("answers a client-error refusal with a malformed code as invalid_request, never server_error", async () => {
		const logger = spyLogger();
		const policies = new Map([["test", refusing(400, 'not "allowed"', "no")]]);

		const res = await request(appFor(policies, undefined, logger)).get("/callback");

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn.mock.calls[0]?.[1]).toBe("redirect_policy_error_malformed");
	});
	it("lets a policy that throws propagate, answering nothing itself", async () => {
		const logger = spyLogger();
		const policy = {
			validateRedirect: () => ({ ok: true as const, value: undefined }),
			resolveCallbackRedirect: () => {
				throw new Error("policy broke");
			},
		} as FederationRedirectPolicy;
		const app = express();
		let thrown: unknown;
		app.get("/callback", (_req, res) => {
			try {
				redirectAfterCallback(
					{ federationRedirectPolicyResolver: new Map([["test", policy]]) },
					provider,
					undefined,
					res,
					logger as unknown as Logger,
				);
			} catch (err) {
				thrown = err;
				res.status(599).end();
			}
		});

		const res = await request(app).get("/callback");

		expect(res.status).toBe(599);
		expect(thrown).toMatchObject({ message: "policy broke" });
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});
});

describe("answerNoRedirectPolicy", () => {
	it("answers 500 internal_error and logs one federation_misconfigured line with the caller's context", async () => {
		const logger = spyLogger();
		const app = express();
		app.get("/start", (_req, res) => {
			answerNoRedirectPolicy(res, logger as unknown as Logger, { provider: "test" });
		});

		const res = await request(app).get("/start");

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
		expect(res.text).toBe(
			'{"error":"internal_error","error_description":"redirect policy not registered for provider"}',
		);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error.mock.calls[0]).toEqual([
			{ provider: "test", reason: "no_redirect_policy" },
			"federation_misconfigured",
		]);
		expect(Object.keys(logger.error.mock.calls[0]?.[0] as object)).toEqual(["provider", "reason"]);
		for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});
});
