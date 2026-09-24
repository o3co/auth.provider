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
import {
	guardedRead,
	LOGGED_STACK_MAX_FRAMES,
	LOGGED_STACK_MAX_LENGTH,
	type LoggableError,
	loggableError,
} from "#/logging/loggableError.mjs";

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

/** The projection without `stack`, whose frames are pinned by cases of their own. */
const shape = (err: unknown): unknown => {
	const walk = (projected: LoggableError): Record<string, unknown> => {
		const { stack: _frames, cause, ...fields } = projected;
		return cause === undefined ? fields : { ...fields, cause: walk(cause) };
	};
	return walk(loggableError(err));
};

describe("loggableError — what a log line may carry of an error", () => {
	it("keeps name, message and code, and the chain of Error causes", () => {
		expect(shape(libraryError())).toEqual({
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
				error_description: "Bad Request",
				cause: { error: "invalid_grant", error_description: "Bad Request" },
			},
		);
		expect(shape(refused)).toEqual({
			name: "ResponseBodyError",
			message: "server responded with an error in the response body",
			code: "OAUTH_RESPONSE_BODY_ERROR",
			status: 400,
			error: "invalid_grant",
			error_description: "Bad Request",
		});
	});

	it("keeps the first line of an error_description written in RFC 6749's character set, and nothing outside it", () => {
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
		expect(described("non-ascii é")).toBeUndefined();
		expect(described(42)).toBeUndefined();
		expect(described("word ".repeat(200))).toHaveLength(256);
		// Only the first line is judged and kept: Azure AD separates a Trace
		// ID, a Correlation ID and a timestamp with CRLF after the AADSTS line.
		expect(described("line\nbreak")).toBe("line");
		expect(
			described(
				"AADSTS70008: The provided authorization code or refresh token has expired due to inactivity.\r\nTrace ID: 0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e\r\nCorrelation ID: 5e4d3c2b-1a0f-9e8d-7c6b-5a4f3e2d1c0b\r\nTimestamp: 2026-09-24 00:00:00Z",
			),
		).toBe(
			"AADSTS70008: The provided authorization code or refresh token has expired due to inactivity.",
		);
	});

	it("cuts an error_description at the start of the word holding its first run of twenty token characters — an echoed credential or identifier", () => {
		// Legacy Spring Security echoes what it refused ("Invalid refresh
		// token: <the token>"); Azure AD and Okta name the client or redirect
		// they refused. A description is the rule's one peer-written string:
		// the words before the one holding the run say what went wrong, and
		// are kept; that word goes whole, so no part of a token and no
		// fragment of it ("https:", "abc:", "'") is left behind.
		const described = (error_description: string) =>
			loggableError(
				Object.assign(new Error("refused"), { error: "invalid_grant", error_description }),
			).error_description;
		expect(
			described(
				"AADSTS700016: Application with identifier 'f1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d' was not found in the directory 'Contoso'.",
			),
		).toBe("AADSTS700016: Application with identifier");
		expect(
			described(
				"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app 'f1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d'.",
			),
		).toBe(
			"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app",
		);
		expect(
			described(
				"AADSTS50011: The redirect URI 'https://app.example.com/auth/callback' specified in the request does not match the redirect URIs configured for the application 'f1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d'.",
			),
		).toBe("AADSTS50011: The redirect URI");
		expect(
			described(
				"The 'redirect_uri' parameter must be a Login redirect URI in the client app settings: https://dev-123456-admin.okta.com/admin/app/oidc_client/instance/0oa1b2c3d4e5f6g7h8i9#tab-general",
			),
		).toBe("The 'redirect_uri' parameter must be a Login redirect URI in the client app settings:");
		expect(described("Invalid refresh token: 3f2a9c1e-7b4d-4c0a-9e8f-7a6b5c4d3e2f")).toBe(
			"Invalid refresh token:",
		);
		// The run starts mid-word: the word goes whole, not just the run.
		expect(described("Invalid refresh token: abc:0gAbCdEfGhIjKlMnOpQrStUv")).toBe(
			"Invalid refresh token:",
		);
		expect(described("Invalid access token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0")).toBe(
			"Invalid access token:",
		);
		// A description that is nothing but a token is omitted.
		expect(described("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0")).toBeUndefined();
		expect(described("  3f2a9c1e7b4d4c0a9e8f7a6b5c4d3e2f")).toBeUndefined();
		// So is one whose first word holds the run, whatever follows it.
		expect(described("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0 is not valid")).toBeUndefined();
		// Google's and Okta's plain descriptions, and a run of nineteen, are kept whole.
		expect(described("Token has been expired or revoked.")).toBe(
			"Token has been expired or revoked.",
		);
		expect(described("The client specified not to prompt, but the user is not logged in.")).toBe(
			"The client specified not to prompt, but the user is not logged in.",
		);
		expect(described("code abcdefghijklmnopqrs expired")).toBe("code abcdefghijklmnopqrs expired");
	});

	it("drops a field of the wrong shape rather than coercing it", () => {
		const odd = Object.assign(new Error("odd"), {
			code: { nested: "at-secret" },
			status: "400",
			error: 'not an error code, it has spaces and a "quote"',
		});
		expect(shape(odd)).toEqual({ name: "Error", message: "odd" });
	});

	it("says only what kind of value was thrown when it is not an Error — in `thrown`", () => {
		expect(shape("at-secret")).toEqual({ name: "NonError", thrown: "string" });
		expect(shape({ access_token: "at-secret" })).toEqual({
			name: "NonError",
			thrown: "object",
		});
		expect(shape(null)).toEqual({ name: "NonError", thrown: "null" });
	});

	it("stops following causes after a few, so a cycle cannot recurse forever", () => {
		const a = new Error("a");
		const b = new Error("b", { cause: a });
		(a as { cause?: unknown }).cause = b;
		const projected = JSON.stringify(loggableError(a));
		expect(projected.match(/"message"/g)?.length).toBeLessThanOrEqual(4);
	});

	describe("the known shapes in which a message quotes a peer are removed", () => {
		it("drops a SyntaxError's message, which quotes the input it could not parse, and keeps the position", () => {
			let failed: unknown;
			try {
				JSON.parse('{"access_token":"ya29.SECRET","token_type":"Bearer"}garbage');
			} catch (err) {
				failed = err;
			}
			expect(shape(failed)).toEqual({ name: "SyntaxError", position: 52 });

			try {
				JSON.parse("gho_SHORTSECRET");
			} catch (err) {
				failed = err;
			}
			expect(shape(failed)).toEqual({ name: "SyntaxError" });
			// The whole projection, frames included: the header that quotes the
			// input is not among them.
			expect(JSON.stringify(loggableError(failed))).not.toContain("SHORTSECRET");
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
			expect(shape(reply)).toEqual({
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
				expect(shape(reply)).toEqual({
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
		expect(shape(onCause)).toEqual({
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
			expect(shape(hostile)).toEqual({ name: "NonError", thrown: "object" });
			// And the fallback still counts a real error.
			expect(shape(new Error("kept"))).toEqual({ name: "Error", message: "kept" });
		} finally {
			if (brand) Object.defineProperty(Error, "isError", brand);
		}
	});

	/*
	 * The shared `stack` vectors. device-grant's copy of this rule
	 * (`packages/device-grant/src/loggableError.mts`) passes the same list;
	 * keep the two in step, so that replacing that copy by this one stays an
	 * import swap. Each vector needs only `loggableError`, the helpers inside
	 * this block and Node's own globals and built-ins.
	 */
	describe("stack — the shared vectors", () => {
		const stackOf = (thrown: unknown): string | undefined =>
			(loggableError(thrown) as { stack?: string }).stack;
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
		function refusesWithAToken(): never {
			throw new TypeError("record for gho_STACKSECRET has no field");
		}

		it("a real TypeError: its frames, and not its message line", () => {
			// A failure in this codebase's own code: without the frames an
			// operator has nothing to find it by.
			const stack = stackOf(thrownBy(() => readsAField(undefined)));
			expect(stack).toMatch(/^ {4}at readsAField /);
			expect(stack).not.toContain("Cannot read properties");
			expect(stack).not.toContain("TypeError");
		});

		it("a token in the message: frames kept, the token not among them", () => {
			const stack = stackOf(thrownBy(refusesWithAToken));
			expect(stack).toMatch(/^ {4}at refusesWithAToken /);
			expect(stack).not.toContain("STACKSECRET");
		});

		it("a frame-shaped line in the message: cut with the message, never kept as a frame", () => {
			const stack = stackOf(
				thrownBy(() => {
					throw new Error("refused\n    at gho_TOKEN (x:1:1)");
				}),
			);
			expect(stack).not.toContain("gho_TOKEN");
			expect(stack).toMatch(/^ {4}at /);
		});

		it("a message rewritten after the first read of `stack`: no stack", () => {
			// V8 formats the stack on its first read; a message changed after it
			// is no longer in the header, and the header cannot be told from the
			// frames.
			const rewritten = thrownBy(refusesWithAToken) as Error;
			void rewritten.stack;
			rewritten.message = "rewritten";
			expect(stackOf(rewritten)).toBeUndefined();
		});

		/** An error whose message hides a frame-shaped line, its stack formatted, then its message set to `message`. */
		const rewrittenTo = (message: unknown, original = "orig\n    at evil (S3CRET:1:1)"): Error => {
			const rewritten = new Error(original);
			void rewritten.stack;
			(rewritten as { message: unknown }).message = message;
			return rewritten;
		};

		it.each(["E", "r", "Err", ": orig", "rig", "o", "Error: orig", ""])(
			"a message rewritten to %j, which the header holds but is not: no stack",
			(message) => {
				// Found anywhere in the stack — inside the name, part-way along the
				// header's line — a message would cut the header short and let the
				// frame-shaped line after it through. Only the whole header, `name:
				// message` ending its line, is accepted.
				expect(stackOf(rewrittenTo(message))).toBeUndefined();
			},
		);

		it("a message rewritten to a leading part of itself that ends mid-line: no stack", () => {
			expect(
				stackOf(rewrittenTo("orig", "orig and more\n    at evil (S3CRET:1:1)")),
			).toBeUndefined();
		});

		it("a message rewritten to a leading part of itself that ends a line: the residual, pinned", () => {
			// The stack's text cannot tell this header from the one V8 would
			// have written for "orig": the old message's next line reads as a
			// frame. The documented residual — `framesOf` names it.
			expect(stackOf(rewrittenTo("orig"))).toMatch(/^ {4}at evil \(S3CRET:1:1\)\n {4}at /);
		});

		it("a custom name with a message found inside it: no stack", () => {
			const named = new Error("orig\n    at evil (S3CRET:1:1)");
			named.name = "MyError";
			void named.stack;
			named.message = "Error";
			expect(stackOf(named)).toBeUndefined();
		});

		it("a message that is not a string: no stack", () => {
			expect(stackOf(rewrittenTo(42))).toBeUndefined();
		});

		it("a name that is not a string compares as Error", () => {
			const unnamed = new Error("m");
			unnamed.stack = "Error: m\n    at a";
			(unnamed as { name: unknown }).name = 42;
			expect(stackOf(unnamed)).toBe("    at a");
		});

		it("Node's coded header, `name [code]: message`: its frames", () => {
			// Buffer.alloc(-1) is a wrong argument to a Node API — a bug in this
			// codebase's own code, where the frames are what finds it.
			const stack = stackOf(thrownBy(() => Buffer.alloc(-1)));
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toContain("ERR_OUT_OF_RANGE");
			expect(stack).not.toContain("out of range");
		});

		it.each([
			["V8's", "Error"],
			["a source-map formatter's", "Error: "],
		])("an empty message under %s header: its frames", (_label, header) => {
			// V8 and Node write an empty message's header as the name alone;
			// source-map-support and vitest's formatter write `name: `.
			const empty = new Error("");
			empty.stack = `${header}\n    at a`;
			expect(stackOf(empty)).toBe("    at a");
		});

		it("a coded header with an empty message, `name [code]`: its frames", () => {
			const coded = Object.assign(new Error(""), { code: "ERR_X" });
			coded.stack = "Error [ERR_X]\n    at a";
			expect(stackOf(coded)).toBe("    at a");
		});

		it("a coded header whose code is not a string: no stack", () => {
			const coded = Object.assign(new Error("m"), { code: 42 });
			coded.stack = "Error [42]: m\n    at a";
			expect(stackOf(coded)).toBeUndefined();
		});

		it.each([
			["new URL's TypeError", "Invalid URL", () => new URL("x")],
			["a JSON SyntaxError", "in JSON", () => JSON.parse("{")],
			[
				"an AggregateError",
				"all failed",
				() => {
					throw new AggregateError([new Error("a")], "all failed");
				},
			],
			[
				"an AggregateError without a message",
				"AggregateError",
				() => {
					throw new AggregateError([new Error("a")]);
				},
			],
			[
				"a DOMException TimeoutError",
				"aborted due to timeout",
				() => {
					throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
				},
			],
		])("%s: its frames, and not its header", (_label, header, fn) => {
			const stack = stackOf(thrownBy(fn));
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toContain(header);
		});

		it("an fs ENOENT: its frames, and not its header", async () => {
			const { readFileSync } = await import("node:fs");
			const stack = stackOf(thrownBy(() => readFileSync("/nonexistent/loggable-error-vector")));
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toContain("ENOENT");
			expect(stack).not.toContain("loggable-error-vector");
		});

		it("an empty message: the frames after a header of the name alone", () => {
			const stack = stackOf(
				thrownBy(() => {
					throw new Error("");
				}),
			);
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toMatch(/^Error/m);
		});

		it("ten frames under Error.stackTraceLimit = 50", () => {
			const limit = Error.stackTraceLimit;
			Error.stackTraceLimit = 50;
			try {
				const recurse = (n: number): never => (n === 0 ? refusesWithAToken() : recurse(n - 1));
				expect(stackOf(thrownBy(() => recurse(30)))?.split("\n")).toHaveLength(10);
			} finally {
				Error.stackTraceLimit = limit;
			}
		});

		it("the 2048-character cut", () => {
			const wide = new Error("wide");
			wide.stack = `Error: wide\n${Array.from(
				{ length: 10 },
				(_, i) => `    at frame${i} (/${"p".repeat(400)}.js:1:1)`,
			).join("\n")}`;
			expect(stackOf(wide)).toHaveLength(2048);
		});

		it("a cause level: the same rule", () => {
			const outer = loggableError(new Error("wrapped", { cause: thrownBy(refusesWithAToken) }));
			const causeStack = (outer as { cause?: { stack?: string } }).cause?.stack;
			expect(causeStack).toMatch(/^ {4}at refusesWithAToken /);
			expect(causeStack).not.toContain("STACKSECRET");
		});

		it("a throwing `stack` getter: no stack, and the rest of the projection", () => {
			const hostile = new Error("kept");
			Object.defineProperty(hostile, "stack", {
				get() {
					throw new Error("stack getter");
				},
			});
			expect(stackOf(hostile)).toBeUndefined();
			expect(loggableError(hostile).message).toBe("kept");
		});

		it("a non-frame line between frames: only the unbroken run before it", () => {
			const broken = new Error("m");
			broken.stack = "Error: m\n    at a\nnot a frame\n    at b";
			expect(stackOf(broken)).toBe("    at a");
		});

		it("a section appended after the frames: not kept, frames in it included", () => {
			const appended = new Error("m");
			appended.stack =
				"Error: m\n    at a\n    at b\nCaused by: Error: inner\n    at gho_SECRET_FRAME (x:1:1)";
			expect(stackOf(appended)).toBe("    at a\n    at b");
		});

		it("no frames: no stack", () => {
			const bare = new Error("bare");
			bare.stack = "Error: bare";
			expect(stackOf(bare)).toBeUndefined();
		});
	});

	it("exports the limits and the guarded read the rule is built from", () => {
		expect(LOGGED_STACK_MAX_FRAMES).toBe(10);
		expect(LOGGED_STACK_MAX_LENGTH).toBe(2048);
		expect(guardedRead({ field: 1 }, "field")).toEqual({ value: 1 });
		expect(guardedRead({}, "absent")).toEqual({ value: undefined });
		const hostile = Object.defineProperty({}, "field", {
			get() {
				throw new Error("getter");
			},
		});
		expect(guardedRead(hostile, "field")).toBeNull();
	});

	it("is compared with toEqual, not toStrictEqual: the constructor pino reads is hidden, not absent", () => {
		// The trap is kept visible here: a strict comparison of a projection
		// with the same fields fails on the non-enumerable `constructor`.
		const projected = loggableError(new Error("kept"));
		const sameFields = { ...projected };
		expect(projected).toEqual(sameFields);
		expect(projected).not.toStrictEqual(sameFields);
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
		let thrown: unknown;
		try {
			throw new TypeError("record for gho_STACKSECRET has no field");
		} catch (err) {
			thrown = err;
		}
		log.error({ err: loggableError(thrown) }, "failed");
		const { err } = JSON.parse(lines[0] ?? "{}") as { err: Record<string, unknown> };
		expect(err.type).toBe("TypeError");
		expect(err.stack).toMatch(/^ {4}at /);
		// The message is this process's own text here, and kept; the stack
		// carries none of it.
		expect(err.stack).not.toContain("STACKSECRET");
	});

	it("counts an error from another realm as an error", () => {
		const foreign = runInNewContext('Object.assign(new Error("from a vm"), { code: "E_VM" })');
		expect(foreign instanceof Error).toBe(false);
		expect(shape(foreign)).toEqual({ name: "Error", message: "from a vm", code: "E_VM" });
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
		expect(shape(hostile)).toEqual({ name: "Error", message: "kept" });
	});
});
