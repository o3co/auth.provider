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
import express, { type NextFunction, type Request, type Response } from "express";
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

	it("logs a Store failure with the closed-set fields an operator triages it by", async () => {
		// The Store's own status (`storeStatus`: 401 or 403, named apart from
		// `status`, which would read here as the client's) says whether the
		// deployment's token was refused or forbidden; a transport failure's
		// `reason` and `code` say what broke. Neither can carry free text.
		const cases = [
			{
				thrown: new StoreCredentialRefusedError("https://store.test/authenticate", 403),
				kept: { name: "StoreCredentialRefusedError", storeStatus: 403 },
			},
			{
				thrown: new StoreTransportError(
					"HttpUserRepository: request to https://store.test/authenticate could not be reached",
					"unreachable",
					"ECONNREFUSED",
				),
				kept: { name: "StoreTransportError", reason: "unreachable", code: "ECONNREFUSED" },
			},
			{
				thrown: new StoreTransportError(
					"HttpUserRepository: the Store closed the connection before answering",
					"connection_closed",
				),
				kept: { name: "StoreTransportError", reason: "connection_closed" },
			},
		];
		for (const { thrown, kept } of cases) {
			const { logger } = serialiseEverythingLogger();
			const app = express();
			app.get("/login", () => {
				throw thrown;
			});
			app.use(createTerminalErrorHandler(logger));

			await request(app).get("/login");

			expect(logger.error, thrown.name).toHaveBeenCalledWith(
				{ err: expect.objectContaining(kept), endpoint: "/login" },
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
					detail: "invalid response encountered",
					code: "OAUTH_INVALID_RESPONSE",
					stack: expect.stringMatching(/^ {4}at /),
					cause: {
						name: "OperationProcessingError",
						detail: '"response" body "scope" property must be a string',
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

describe("terminal error handler — the endpoint it logs is the caller's path", () => {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
	const CONTROL = /[\u0000-\u001f\u007f]/;
	/** What an assertion needs of a logged string: a failure prints this, not the string. */
	const shapeOf = (text: unknown) => ({
		string: typeof text === "string",
		control: CONTROL.test(String(text)),
		within200: String(text).length <= 200,
	});
	const BOUNDED = { string: true, control: false, within200: true };

	/** The one error line, and nothing at warn. */
	const onlyError = (logger: Logger, error: ReturnType<typeof vi.fn>) => {
		expect(error).toHaveBeenCalledTimes(1);
		expect(logger.warn).not.toHaveBeenCalled();
		const [line, event] = error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("unhandled_request_error");
		expect(line.err).not.toBeInstanceOf(Error);
		return line;
	};

	it("logs a 10 000-character path capped", async () => {
		const { logger, error } = makeLogger();
		const app = express();
		app.get(/^\/boom/, () => {
			throw new Error("route exploded");
		});
		app.use(createTerminalErrorHandler(logger));

		const res = await request(app).get(`/boom/${"a".repeat(10_000)}`);

		expect(res.status).toBe(500);
		expect(shapeOf(onlyError(logger, error).endpoint)).toEqual(BOUNDED);
	});

	it("logs a path carrying a line break and control characters sanitised", () => {
		// A real HTTP client refuses to send these in a request target; a
		// lenient parser, or another server in front, is what could hand one on.
		const { logger, error } = makeLogger();
		const res = { headersSent: false, status: vi.fn(), json: vi.fn() };
		res.status.mockReturnValue(res);
		const next = vi.fn();

		createTerminalErrorHandler(logger)(
			new Error("route exploded"),
			{
				path: `/boom\r\nFORGED unhandled_request_error\u001b[31m\u0000\u0007${"a".repeat(10_000)}`,
			} as Request,
			res as unknown as Response,
			next as unknown as NextFunction,
		);

		expect(res.status).toHaveBeenCalledWith(500);
		expect(next).not.toHaveBeenCalled();
		const endpoint = onlyError(logger, error).endpoint;
		expect(shapeOf(endpoint)).toEqual(BOUNDED);
		expect(String(endpoint).startsWith("/boom??FORGED")).toBe(true);
	});
});
