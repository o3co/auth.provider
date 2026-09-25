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
 * The lines this package writes (#593, D18): object-first with the event as
 * the message, every string field sanitised and capped, and a caught error as
 * core's projection — which keeps what an operator needs (the name, the
 * message, the code, an upstream's `error`) and drops what a library put
 * beside it (a response body, a command's arguments, a token answer on a
 * cause).
 */

import { consoleLogger } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createFederationGrantLog } from "#/log.mjs";
import { createLogSpy, payloadOf, written } from "./logSpy.mjs";

const SENTINEL = "SENTINEL-refresh-token-do-not-log";

afterEach(() => {
	vi.restoreAllMocks();
});

describe("createFederationGrantLog", () => {
	it("writes an outage at error and a degraded path at warn, object-first, with the cause projected", () => {
		const { logger, lines } = createLogSpy();
		const log = createFederationGrantLog(logger);
		log.outage("x_unavailable", { store: "federation_grant", step: "open" }, new Error("down"));
		log.degraded("x_step_failed", { step: "touch" }, new Error("slow"));
		expect(written(lines)).toEqual(["error x_unavailable", "warn x_step_failed"]);
		expect(payloadOf(lines, "x_unavailable")).toEqual({
			store: "federation_grant",
			step: "open",
			err: expect.objectContaining({ name: "Error", detail: "down" }),
		});
	});

	it("carries no err for a line with no cause, and one for a cause that is undefined", () => {
		const { logger, lines } = createLogSpy();
		const log = createFederationGrantLog(logger);
		log.outage("no_cause", { reason: "key_unavailable" });
		log.outage("thrown_undefined", { reason: "storage" }, undefined);
		expect(payloadOf(lines, "no_cause")).toEqual({ reason: "key_unavailable" });
		expect(payloadOf(lines, "thrown_undefined")).toEqual({
			reason: "storage",
			err: { name: "NonError", thrown: "undefined" },
		});
	});

	it("leaves an undefined field out, and sanitises and caps every string", () => {
		const { logger, lines } = createLogSpy();
		createFederationGrantLog(logger).outage("line", {
			grantId: `g-1"\r\nforged: 1${"x".repeat(300)}`,
			store: undefined,
			retryAfterSeconds: 30,
		});
		const payload = payloadOf(lines, "line");
		expect(payload).not.toHaveProperty("store");
		expect(payload.retryAfterSeconds).toBe(30);
		expect(payload.grantId).toMatch(/^g-1\?\?\?forged: 1x+\.\.\.$/);
		expect((payload.grantId as string).length).toBe(200);
	});

	it("keeps what a library put beside an error's message out of the line", () => {
		// openid-client puts the token answer it refused on the cause chain,
		// ioredis a refused command's arguments on the error, an HTTP client the
		// response. None of it reaches the line; the name, the code, the upstream's
		// `error` and a first-line `error_description` cut before anything
		// token-shaped do.
		const { logger, lines } = createLogSpy();
		const upstream = Object.assign(new Error("server responded with an error"), {
			error: "invalid_grant",
			error_description: `Invalid refresh token: ${SENTINEL}`,
			body: { refresh_token: SENTINEL },
			command: { name: "evalsha", args: [SENTINEL] },
			cause: Object.assign(new Error("response"), { body: SENTINEL }),
		});
		createFederationGrantLog(logger).degraded("refused", {}, upstream);
		expect(JSON.stringify(lines)).not.toContain(SENTINEL);
		expect(payloadOf(lines, "refused").err).toMatchObject({
			name: "Error",
			error: "invalid_grant",
			error_description: "Invalid refresh token:",
			command: { name: "evalsha" },
		});
	});

	it("writes what escaped a handler as federation_grants_unexpected_error, with its site", () => {
		const { logger, lines } = createLogSpy();
		const log = createFederationGrantLog(logger);
		log.unexpected("token", { grantId: "g-1" }, new TypeError("bug"));
		log.unexpected("federation_grants", { correlationId: "c-1" }, new Error("escaped"));
		expect(written(lines)).toEqual([
			"error federation_grants_unexpected_error",
			"error federation_grants_unexpected_error",
		]);
		expect(lines[0]?.args[0]).toEqual({
			site: "token",
			grantId: "g-1",
			err: expect.objectContaining({ name: "TypeError", detail: "bug" }),
		});
		expect(lines[1]?.args[0]).toEqual({
			site: "federation_grants",
			correlationId: "c-1",
			err: expect.objectContaining({ name: "Error", detail: "escaped" }),
		});
	});

	it("writes a client registry that cannot answer as core's one line, with the site", () => {
		const { logger, lines } = createLogSpy();
		createFederationGrantLog(logger).clientRepositoryUnavailable(
			"federation_grant_consent",
			"worker",
			new Error("registry down"),
		);
		expect(payloadOf(lines, "client_repository_unavailable")).toEqual({
			site: "federation_grant_consent",
			step: "find",
			clientId: "worker",
			err: expect.objectContaining({ name: "Error", detail: "registry down" }),
		});
	});

	it("writes to the console logger when the deployment wired none — never nowhere", () => {
		const error = vi.spyOn(consoleLogger, "error").mockImplementation(() => undefined);
		createFederationGrantLog(undefined).outage(
			"x_unavailable",
			{ step: "open" },
			new Error("down"),
		);
		expect(error).toHaveBeenCalledTimes(1);
		expect(error.mock.calls[0]?.[1]).toBe("x_unavailable");
	});
});
