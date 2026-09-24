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

import { runInNewContext } from "node:vm";
import express from "express";
import pino from "pino";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { loggableError } from "../loggableError.mjs";

/** The shape openid-client throws for a token response it refuses: the body two causes down. */
const libraryError = (): Error => {
	const body = { access_token: "at-secret", refresh_token: "rt-secret", scope: 42 };
	const processing = Object.assign(
		new Error('"response" body "scope" property must be a string', { cause: { body } }),
		{ name: "OperationProcessingError", code: "OAUTH_INVALID_RESPONSE" },
	);
	return Object.assign(new Error("invalid response encountered", { cause: processing }), {
		name: "ClientError",
		code: "OAUTH_INVALID_RESPONSE",
	});
};

/** What express's JSON body parser (body-parser) hands the error handler for a request body. */
const bodyParserError = async (
	body: string,
	options: { limit?: string } = {},
): Promise<unknown> => {
	let caught: unknown;
	const app = express();
	app.use(express.json(options));
	app.post("/", (_req, res) => {
		res.status(204).end();
	});
	app.use(
		(err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
			caught = err;
			res.status(400).end();
		},
	);
	await request(app).post("/").set("content-type", "application/json").send(body);
	return caught;
};

describe("loggableError — what a log line may carry of an error", () => {
	it("keeps name, message and code, and the chain of Error causes", () => {
		expect(loggableError(libraryError())).toEqual({
			name: "ClientError",
			message: "invalid response encountered",
			code: "OAUTH_INVALID_RESPONSE",
			cause: {
				name: "OperationProcessingError",
				message: '"response" body "scope" property must be a string',
				code: "OAUTH_INVALID_RESPONSE",
			},
		});
	});

	it("never carries a cause that is not an Error — where a library puts the response body", () => {
		const serialised = JSON.stringify(loggableError(libraryError()));
		expect(serialised).not.toContain("at-secret");
		expect(serialised).not.toContain("rt-secret");
		expect(serialised).not.toContain("access_token");
	});

	it("keeps an HTTP status and an OAuth error code, which say what the upstream answered", () => {
		const refused = Object.assign(
			new Error("server responded with an error in the response body"),
			{
				name: "ResponseBodyError",
				code: "OAUTH_RESPONSE_BODY_ERROR",
				status: 400,
				error: "invalid_grant",
				cause: { error: "invalid_grant" },
			},
		);
		expect(loggableError(refused)).toEqual({
			name: "ResponseBodyError",
			message: "server responded with an error in the response body",
			code: "OAUTH_RESPONSE_BODY_ERROR",
			status: 400,
			error: "invalid_grant",
		});
	});

	it("keeps an error_description written in RFC 6749's character set, and nothing outside it", () => {
		const described = (error_description: unknown) =>
			loggableError(
				Object.assign(new Error("server responded with an error in the response body"), {
					error: "invalid_grant",
					error_description,
				}),
			).error_description;
		// What an operator needs to tell a revoked grant from a misconfigured client.
		expect(described("Token has been expired or revoked.")).toBe(
			"Token has been expired or revoked.",
		);
		expect(described('a "quoted" value')).toBeUndefined();
		expect(described("line\nbreak")).toBeUndefined();
		expect(described("non-ascii é")).toBeUndefined();
		expect(described(42)).toBeUndefined();
		expect(described("x".repeat(1000))).toHaveLength(256);
	});

	it("drops a field of the wrong shape rather than coercing it", () => {
		const odd = Object.assign(new Error("odd"), {
			code: { nested: "at-secret" },
			status: "400",
			error: 'not an error code, it has spaces and a "quote"',
		});
		expect(loggableError(odd)).toEqual({ name: "Error", message: "odd" });
	});

	it("says only what kind of value was thrown when it is not an Error — in `thrown`", () => {
		expect(loggableError("at-secret")).toEqual({ name: "NonError", thrown: "string" });
		expect(loggableError({ access_token: "at-secret" })).toEqual({
			name: "NonError",
			thrown: "object",
		});
		expect(loggableError(null)).toEqual({ name: "NonError", thrown: "null" });
	});

	it("stops following causes after a few, so a cycle cannot recurse forever", () => {
		const a = new Error("a");
		const b = new Error("b", { cause: a });
		(a as { cause?: unknown }).cause = b;
		const projected = JSON.stringify(loggableError(a));
		expect(projected.match(/"message"/g)?.length).toBeLessThanOrEqual(4);
	});

	describe("a message a parser or a peer wrote is not trusted", () => {
		it("drops a SyntaxError's message, which quotes the input it could not parse, and keeps the position", () => {
			let failed: unknown;
			try {
				JSON.parse('{"access_token":"ya29.SECRET","token_type":"Bearer"}garbage');
			} catch (err) {
				failed = err;
			}
			expect(loggableError(failed)).toEqual({ name: "SyntaxError", position: 52 });

			try {
				JSON.parse("gho_SHORTSECRET");
			} catch (err) {
				failed = err;
			}
			const projected = loggableError(failed);
			expect(projected).toEqual({ name: "SyntaxError" });
			expect(JSON.stringify(projected)).not.toContain("SHORTSECRET");
		});

		it("cuts the arguments out of a Redis reply error, which echoes the command it refused", () => {
			// redis-errors' ReplyError (ioredis), and node-redis's ErrorReply,
			// carry the server's text; Redis quotes the leading arguments.
			const reply = Object.assign(
				new Error(
					"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'",
				),
				{ name: "ReplyError", command: { name: "evalsha", args: ["sha", "1", "user-1"] } },
			);
			expect(loggableError(reply)).toEqual({
				name: "ReplyError",
				message: "ERR unknown command 'evalsha'",
			});
		});

		it("cuts Redis's echo from any message, whichever client's class carries it", () => {
			// node-redis's ErrorReply / SimpleError / BlobError set no name, so
			// they are "Error"; the server writes the same text for every client.
			const text =
				"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'";
			class ErrorReply extends Error {}
			class SimpleError extends ErrorReply {}
			for (const reply of [new Error(text), new ErrorReply(text), new SimpleError(text)]) {
				expect(loggableError(reply)).toEqual({
					name: "Error",
					message: "ERR unknown command 'evalsha'",
				});
			}
		});

		it("reads a SyntaxError's position only as ' at position N', N at most ten digits", () => {
			const at = (message: string) => loggableError(new SyntaxError(message)).position;
			expect(at("Unexpected token at position 1234567890 (line 1 column 1234567891)")).toBe(
				1234567890,
			);
			// A longer number is no position at all, never its first ten digits.
			expect(at("Unexpected token at position 12345678901")).toBeUndefined();
			expect(at("Unexpected token at position 12345678901234")).toBeUndefined();
			expect(at("Unexpected end of JSON input")).toBeUndefined();
			expect(at("positional nonsense, position 7")).toBeUndefined();
		});

		it("keeps body-parser's `type` and status, and never the body or the parser's message", async () => {
			const malformed = await bodyParserError('{"access_token":gho_SECRET1234567890}');
			const parsed = loggableError(malformed);
			expect(parsed).toMatchObject({
				name: "SyntaxError",
				status: 400,
				type: "entity.parse.failed",
			});
			expect(JSON.stringify(parsed)).not.toContain("SECRET");

			const large = await bodyParserError(JSON.stringify({ padding: "x".repeat(200) }), {
				limit: "10b",
			});
			expect(loggableError(large)).toMatchObject({ status: 413, type: "entity.too.large" });
		});
	});

	it("keeps the status and content type of a Response the library put on the error", () => {
		// openid-client's "unexpected HTTP response status code": a gateway's
		// 503 page is the Response on the cause, and the 503 is what matters.
		const gateway = new Response("<html>Service Unavailable</html>", {
			status: 503,
			headers: { "content-type": "text/html; charset=utf-8" },
		});
		const onCause = Object.assign(
			new Error("unexpected HTTP response status code", { cause: gateway }),
			{ name: "ClientError", code: "OAUTH_RESPONSE_IS_NOT_CONFORM" },
		);
		expect(loggableError(onCause)).toEqual({
			name: "ClientError",
			message: "unexpected HTTP response status code",
			code: "OAUTH_RESPONSE_IS_NOT_CONFORM",
			response: { status: 503, contentType: "text/html; charset=utf-8" },
		});

		const own = Object.assign(new Error("server responded with an error in the response body"), {
			response: new Response("{}", {
				status: 401,
				headers: { "content-type": "application/json" },
			}),
		});
		expect(loggableError(own).response).toEqual({ status: 401, contentType: "application/json" });
	});

	it("caps every string it keeps at 256 characters", () => {
		const long = Object.assign(new Error("m".repeat(1000)), {
			name: "N".repeat(1000),
			code: "C".repeat(1000),
			type: "t".repeat(1000),
		});
		const projected = loggableError(long);
		expect(projected.message).toHaveLength(256);
		expect(projected.name).toHaveLength(256);
		expect(projected.code).toHaveLength(256);
		expect(projected.type).toHaveLength(256);
	});

	it("does not throw on a value whose prototype cannot be read, where Error.isError is missing", () => {
		// Node 22, the engines floor, has no Error.isError; the fallback's
		// `instanceof` asks the value for its prototype, and a Proxy may throw.
		const hostile = new Proxy(
			{},
			{
				getPrototypeOf() {
					throw new Error("trap");
				},
				get() {
					throw new Error("trap");
				},
			},
		);
		const brand = Object.getOwnPropertyDescriptor(Error, "isError");
		delete (Error as { isError?: unknown }).isError;
		try {
			expect(loggableError(hostile)).toEqual({ name: "NonError", thrown: "object" });
			// And the fallback still counts a real error.
			expect(loggableError(new Error("kept"))).toEqual({ name: "Error", message: "kept" });
		} finally {
			if (brand) Object.defineProperty(Error, "isError", brand);
		}
	});

	describe("stack: the frames, never the header line that carries the message", () => {
		/** What the function under inspection threw. */
		const thrownBy = (fn: () => unknown): unknown => {
			try {
				fn();
			} catch (err) {
				return err;
			}
			throw new Error("expected a throw");
		};

		function readsAField(record: unknown): number {
			return (record as { field: { value: number } }).field.value;
		}
		function refusesTheRecord(): never {
			throw new TypeError("record for gho_STACKSECRET has no field");
		}

		it("keeps a real TypeError's frames, and not its message line — a token in the message included", () => {
			// A failure in this codebase's own code: without the frames an
			// operator has nothing to find it by.
			const natural = loggableError(thrownBy(() => readsAField(undefined)));
			expect(natural.stack).toMatch(/^ {4}at readsAField /);
			expect(natural.stack).not.toContain("Cannot read properties");

			const worded = loggableError(thrownBy(refusesTheRecord));
			expect(worded.stack).toMatch(/^ {4}at refusesTheRecord /);
			expect(worded.stack).not.toContain("STACKSECRET");
			expect(worded.stack).not.toContain("TypeError");
		});

		it("drops a message line that looks like a frame: a peer cannot write a frame into the stack", () => {
			const injected = loggableError(
				thrownBy(() => {
					throw new Error("refused\n    at gho_INJECTED (upstream.js:1:1)");
				}),
			);
			expect(injected.stack).not.toContain("INJECTED");
			expect(injected.stack).toMatch(/^ {4}at /);
		});

		it("keeps at most ten frames and 2048 characters, whichever comes first", () => {
			const limit = Error.stackTraceLimit;
			Error.stackTraceLimit = 50;
			try {
				const recurse = (n: number): never => (n === 0 ? refusesTheRecord() : recurse(n - 1));
				const deep = loggableError(thrownBy(() => recurse(30)));
				expect(deep.stack?.split("\n")).toHaveLength(10);
			} finally {
				Error.stackTraceLimit = limit;
			}
			const wide = new Error("wide");
			wide.stack = `Error: wide\n${Array.from(
				{ length: 10 },
				(_, i) => `    at frame${i} (/${"p".repeat(400)}.js:1:1)`,
			).join("\n")}`;
			expect(loggableError(wide).stack).toHaveLength(2048);
		});

		it("keeps no stack that has no frames", () => {
			const bare = new Error("bare");
			bare.stack = "Error: bare";
			expect("stack" in loggableError(bare)).toBe(false);
		});

		it("applies the same rule at every cause", () => {
			const inner = thrownBy(refusesTheRecord);
			const outer = loggableError(new Error("wrapped", { cause: inner }));
			expect(outer.cause?.stack).toMatch(/^ {4}at refusesTheRecord /);
			expect(outer.cause?.stack).not.toContain("STACKSECRET");
		});

		it("reaches pino as the error's name for `type` and its frames for `stack`", () => {
			const lines: string[] = [];
			const log = pino(
				{ base: null, timestamp: false },
				{
					write(line: string) {
						lines.push(line);
					},
				},
			);
			log.error({ err: loggableError(thrownBy(refusesTheRecord)) }, "failed");
			const { err } = JSON.parse(lines[0] ?? "{}") as { err: Record<string, unknown> };
			expect(err.type).toBe("TypeError");
			expect(err.stack).toMatch(/^ {4}at refusesTheRecord /);
			expect(JSON.stringify(err)).not.toContain("STACKSECRET");
		});
	});

	it("counts an error from another realm as an error", () => {
		const foreign = runInNewContext('Object.assign(new Error("from a vm"), { code: "E_VM" })');
		expect(foreign instanceof Error).toBe(false);
		expect(loggableError(foreign)).toEqual({ name: "Error", message: "from a vm", code: "E_VM" });
	});

	it("does not throw when a field's getter does, and leaves that field out", () => {
		const hostile = new Error("kept");
		for (const field of ["code", "status", "cause", "name"]) {
			Object.defineProperty(hostile, field, {
				get() {
					throw new Error(`${field} getter`);
				},
			});
		}
		expect(loggableError(hostile)).toEqual({ name: "Error", message: "kept" });
	});
});
