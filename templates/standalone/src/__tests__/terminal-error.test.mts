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
import { type Logger, loggableError } from "@o3co/auth-provider-core";
import { StoreCredentialRefusedError, StoreTransportError } from "@o3co/auth-provider-foundation";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createTerminalErrorHandler } from "../terminalError.mjs";

const makeLogger = () => {
	const error = vi.fn();
	const logger = {
		error,
		warn: vi.fn(),
		info: vi.fn(),
		debug: vi.fn(),
	} as unknown as Logger;
	return { logger, error };
};

/**
 * A logger that serialises every own property of what it is handed, `cause`
 * and non-enumerable fields included — a deployment is free to install one.
 * `lines` is what it wrote; its levels are spies.
 */
const serialiseEverythingLogger = () => {
	const lines: string[] = [];
	const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
		if (typeof value !== "object" || value === null) return value;
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		const out: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(value)) {
			out[key] = walk((value as Record<string, unknown>)[key], seen);
		}
		return out;
	};
	const record = (level: string) =>
		vi.fn((...args: unknown[]): void => {
			lines.push(JSON.stringify({ level, args: walk(args) }));
		});
	const logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	return { logger: logger as typeof logger & Logger, lines };
};

const makeApp = (logger: Logger) => {
	const app = express();
	app.use(express.json());
	app.post("/echo", (_req, res) => {
		res.status(200).json({ ok: true });
	});
	app.get("/boom", () => {
		throw new Error("route exploded");
	});
	app.use(createTerminalErrorHandler(logger));
	return app;
};

describe("terminal error handler (#293 item 8)", () => {
	it("answers malformed JSON with the client's 400 in the shared envelope, not Express's HTML page", async () => {
		const { logger, error } = makeLogger();
		const res = await request(makeApp(logger))
			.post("/echo")
			.set("Content-Type", "application/json")
			.send("{not json");

		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toContain("application/json");
		expect(res.body.error).toBe("invalid_request");
		// The client's malformed body is not a server error worth an error line.
		expect(error).not.toHaveBeenCalled();
	});

	it("keeps the body parser's own status for an over-limit body (413)", async () => {
		const { logger } = makeLogger();
		const app = express();
		app.use(express.json({ limit: 16 }));
		app.post("/echo", (_req, res) => {
			res.status(200).json({ ok: true });
		});
		app.use(createTerminalErrorHandler(logger));

		const res = await request(app)
			.post("/echo")
			.set("Content-Type", "application/json")
			.send(JSON.stringify({ pad: "x".repeat(64) }));

		expect(res.status).toBe(413);
		expect(res.body.error).toBe("invalid_request");
		expect(res.body.error_description).toBe("request body too large");
	});

	it("answers an unexpected route throw with 500 server_error and logs it structurally", async () => {
		const { logger, error } = makeLogger();
		const res = await request(makeApp(logger)).get("/boom");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			error: "server_error",
			error_description: "Internal server error",
		});
		// No stack trace on the wire — the envelope is the whole body.
		expect(JSON.stringify(res.body)).not.toContain("route exploded");
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ endpoint: "/boom" }),
			"unhandled_request_error",
		);
	});

	it("answers a Store failure a route did not catch as 500 and logs it — the Store's own status is not the client's", async () => {
		// The user repository's named errors reach here only if a route lets
		// one through. Their Store status must not be read as the answer: an
		// error carrying a numeric 4xx `status` is taken for a body-parser
		// rejection, answered with that status and not logged — so a Store that
		// refused this deployment's token would reach the browser as its own
		// 401 "malformed request body", with nothing in the log.
		for (const make of [
			() => new StoreCredentialRefusedError("https://store.test/authenticate", 401),
			() => new StoreCredentialRefusedError("https://store.test/authenticate", 403),
			() =>
				new StoreTransportError(
					"HttpUserRepository: request to https://store.test/authenticate could not be reached",
					"unreachable",
					"ECONNREFUSED",
				),
		]) {
			const thrown = make();
			const { logger, error } = makeLogger();
			const app = express();
			app.get("/login", () => {
				throw thrown;
			});
			app.use(createTerminalErrorHandler(logger));

			const res = await request(app).get("/login");

			expect(res.status, thrown.message).toBe(500);
			expect(res.body).toEqual({
				error: "server_error",
				error_description: "Internal server error",
			});
			expect(error).toHaveBeenCalledWith(
				{ err: loggableError(thrown), endpoint: "/login" },
				"unhandled_request_error",
			);
		}
	});

	it("logs an unhandled error as loggableError's projection, never what an upstream put on it", async () => {
		// An OAuth library that refuses a token answer puts the answer — the
		// tokens included — on its error's cause chain, and a route that lets
		// the error through hands it here. The frames and the name locate the
		// failure; the answer is the upstream's, and never the log's.
		const answer = { access_token: "at-UPSTREAM-S3CRET", refresh_token: "rt-UPSTREAM-S3CRET" };
		const refused = Object.assign(
			new Error("invalid response encountered", {
				cause: Object.assign(
					new Error('"response" body "scope" property must be a string', {
						cause: { body: answer },
					}),
					{ name: "OperationProcessingError", code: "OAUTH_INVALID_RESPONSE" },
				),
			}),
			{ name: "ClientError", code: "OAUTH_INVALID_RESPONSE" },
		);
		const { logger, lines } = serialiseEverythingLogger();
		const app = express();
		app.get("/federation/callback", () => {
			throw refused;
		});
		app.use(createTerminalErrorHandler(logger));

		const res = await request(app).get("/federation/callback");

		expect(res.status).toBe(500);
		expect(logger.error).toHaveBeenCalledWith(
			{
				err: {
					name: "ClientError",
					message: "invalid response encountered",
					code: "OAUTH_INVALID_RESPONSE",
					stack: expect.stringMatching(/^ {4}at /),
					cause: {
						name: "OperationProcessingError",
						message: '"response" body "scope" property must be a string',
						code: "OAUTH_INVALID_RESPONSE",
						stack: expect.stringMatching(/^ {4}at /),
					},
				},
				endpoint: "/federation/callback",
			},
			"unhandled_request_error",
		);
		for (const line of lines) expect(line).not.toContain("UPSTREAM-S3CRET");
	});
});
