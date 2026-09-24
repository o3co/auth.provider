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
 * What of an error a log line may carry — the rule core's `loggableError`
 * follows. The mounted routes' tests pin that the routes use this; these pin
 * the rule, against errors shaped as the real ones are: `JSON.parse`'s own
 * SyntaxErrors, and Redis error replies as ioredis (redis-errors'
 * `ReplyError`) and node-redis (`ErrorReply`, whose `name` is `"Error"`)
 * raise them. This package depends on no Redis client, so those two are
 * built here with Redis's exact text rather than imported.
 */

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import {
	LOGGED_STACK_MAX_FRAMES,
	LOGGED_STACK_MAX_LENGTH,
	LOGGED_STRING_MAX_LENGTH,
	loggableError,
} from "#/loggableError.mjs";

/** Redis's own reply to an unknown command, which quotes the command's first arguments. */
const REDIS_UNKNOWN_COMMAND =
	"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'";

/** ioredis raises redis-errors' `ReplyError`, whose `name` is `"ReplyError"`. */
class ReplyError extends Error {
	override name = "ReplyError";
}

/** node-redis raises `ErrorReply` (and `SimpleError`, `BlobError`) without setting `name`. */
class ErrorReply extends Error {}

const parseErrorOf = (input: string): Error => {
	try {
		JSON.parse(input);
	} catch (error) {
		return error as Error;
	}
	throw new Error("parsed");
};

/** A projection's `stack`: frames only, from the first. */
const FRAMES = expect.stringMatching(/^ {4}at /);

/** What `fn` threw. */
const thrownBy = (fn: () => unknown): unknown => {
	try {
		fn();
	} catch (error) {
		return error;
	}
	throw new Error("expected a throw");
};

function readsAField(record: unknown): number {
	return (record as { field: { value: number } }).field.value;
}

function refusesTheRecord(): never {
	throw new TypeError("record for gho_STACKSECRET has no field");
}

describe("loggableError", () => {
	it("keeps name, message, type, code and status of an Error — nothing else, nothing nested", () => {
		const error = Object.assign(new Error("outer"), {
			code: "E_X",
			status: 503,
			type: "store.failed",
			body: "client_secret=s3cret",
			command: { args: ["BCDFGHJK"] },
			cause: new Error("inner s3cret"),
		});
		expect(loggableError(error)).toEqual({
			name: "Error",
			message: "outer",
			type: "store.failed",
			code: "E_X",
			status: 503,
			stack: FRAMES,
		});
	});

	it("keeps `type` only as a string, as body-parser and http-errors set it", () => {
		expect(loggableError(Object.assign(new Error("m"), { type: 42 }))).toEqual({
			name: "Error",
			message: "m",
			stack: FRAMES,
		});
	});

	it.each([
		["a plain Error", new Error(REDIS_UNKNOWN_COMMAND), "Error"],
		["ioredis's ReplyError", new ReplyError(REDIS_UNKNOWN_COMMAND), "ReplyError"],
		["node-redis's ErrorReply, named Error", new ErrorReply(REDIS_UNKNOWN_COMMAND), "Error"],
	])(
		"cuts the command arguments Redis quotes, whatever class carries them (%s)",
		(_label, error, name) => {
			// The phrase is Redis's own, so the cut is keyed on it rather than on
			// the client library's class name.
			expect(loggableError(error)).toEqual({
				name,
				message: "ERR unknown command 'evalsha'",
				stack: FRAMES,
			});
		},
	);

	it("drops a real JSON.parse SyntaxError's message, keeping the position it names", () => {
		// V8 quotes its input there; body-parser's `entity.parse.failed` is one
		// quoting the request body.
		expect(loggableError(parseErrorOf('{"user_code":"BCDFGHJK","sub":"user-1"'))).toEqual({
			name: "SyntaxError",
			position: 38,
			stack: FRAMES,
		});
		const quoted = loggableError(parseErrorOf("user_code=BCDFGHJK&sub=user-1"));
		expect(quoted).toEqual({ name: "SyntaxError", stack: FRAMES });
		expect(quoted.stack).not.toContain("BCDFGHJK");
	});

	it("keeps a position only when it is at most ten digits", () => {
		const huge = new SyntaxError("Unexpected end of JSON input at position 12345678901234");
		expect(loggableError(huge)).toEqual({ name: "SyntaxError", stack: FRAMES });
	});

	it("caps every string it keeps at 256 characters", () => {
		const projected = loggableError(
			Object.assign(new Error("m".repeat(1000)), {
				code: "c".repeat(1000),
				type: "t".repeat(1000),
			}),
		);
		expect(LOGGED_STRING_MAX_LENGTH).toBe(256);
		for (const key of ["message", "code", "type"] as const) {
			expect(String(projected[key]).length, key).toBe(256);
		}
	});

	it("leaves out a field whose read throws, and never throws itself", () => {
		const error = new Error("m");
		Object.defineProperty(error, "code", {
			get() {
				throw new Error("getter");
			},
		});
		Object.defineProperty(error, "status", {
			get() {
				throw new Error("getter");
			},
		});
		expect(loggableError(error)).toEqual({ name: "Error", message: "m", stack: FRAMES });
	});

	it("reports a thrown value that is not an Error by its type alone", () => {
		expect(loggableError("boom s3cret")).toEqual({ thrown: "string" });
		expect(loggableError(42)).toEqual({ thrown: "number" });
		expect(loggableError(null)).toEqual({ thrown: "object" });
		expect(loggableError({ message: "m s3cret", code: "E" })).toEqual({ thrown: "object" });
	});

	describe("stack: the frames, never the header line that carries the message", () => {
		it("keeps a real TypeError's frames, and not its message line — a token in the message included", () => {
			// A failure in this package's own code: without the frames an
			// operator has nothing to find it by.
			const natural = loggableError(thrownBy(() => readsAField(undefined)));
			expect(natural.stack).toMatch(/^ {4}at readsAField /);
			expect(natural.stack).not.toContain("Cannot read properties");

			const worded = loggableError(thrownBy(refusesTheRecord));
			expect(worded.stack).toMatch(/^ {4}at refusesTheRecord /);
			expect(worded.stack).not.toContain("STACKSECRET");
			expect(worded.stack).not.toContain("TypeError");
		});

		it("drops a message line that looks like a frame: a caller cannot write a frame into the stack", () => {
			const injected = loggableError(
				thrownBy(() => {
					throw new Error("refused\n    at gho_TOKEN (x:1:1)");
				}),
			);
			expect(injected.stack).not.toContain("gho_TOKEN");
			expect(injected.stack).toMatch(/^ {4}at /);
		});

		it("drops the one-line header of an error with an empty message", () => {
			const empty = loggableError(
				thrownBy(() => {
					throw new Error("");
				}),
			);
			expect(empty.stack).toMatch(/^ {4}at /);
			expect(empty.stack).not.toMatch(/^Error/m);
		});

		it("keeps the unbroken run of frames from the first, and nothing after a line that is not one", () => {
			const interleaved = new Error("m");
			interleaved.stack = "Error: m\n    at a\nnot a frame\n    at b";
			expect(loggableError(interleaved).stack).toBe("    at a");
		});

		it("drops a `Caused by:` section appended after the frames", () => {
			const appended = new Error("m");
			appended.stack =
				"Error: m\n    at a (x.js:1:1)\nCaused by: Error: x\n    at gho_SECRET_FRAME (x:1:1)";
			const { stack } = loggableError(appended);
			expect(stack).toBe("    at a (x.js:1:1)");
			expect(stack).not.toContain("gho_SECRET_FRAME");
		});

		it("keeps no stack whose header no longer carries the message, as it cannot tell header from frames", () => {
			// The message was rewritten after the stack was formatted — V8 does
			// that on the first read of `stack`, from the message as it is then:
			// what the header carries instead is unknown, and may be shaped like
			// a frame.
			const rewritten = new Error("refused\n    at gho_TOKEN (x:1:1)");
			expect(rewritten.stack).toContain("gho_TOKEN");
			rewritten.message = "upstream refused the request";
			expect("stack" in loggableError(rewritten)).toBe(false);
		});

		/**
		 * An error whose message carried a frame-shaped line, its stack formatted
		 * (V8 does that on the first read of `stack`), then `rewrite` applied.
		 */
		const rewrittenAfterFormatting = (
			rewrite: (error: Error) => void,
			message = "orig\n    at evil (S3CRET:1:1)",
		): Error => {
			const error = new Error(message);
			expect(error.stack).toContain("S3CRET");
			rewrite(error);
			return error;
		};

		it.each(["E", "r", "Err", ": orig", "rig", "o", "Error: orig", ""])(
			"keeps no stack when the message is rewritten to %j after the stack was formatted",
			(message) => {
				// A cut found anywhere in the stack could fall inside the header,
				// and the header's frame-shaped line would then read as a frame.
				// The header must be the stack's start, and end its line.
				const projected = loggableError(
					rewrittenAfterFormatting((error) => {
						error.message = message;
					}),
				);
				expect("stack" in projected).toBe(false);
			},
		);

		it("keeps no stack when the name and message are rewritten to another header", () => {
			const projected = loggableError(
				rewrittenAfterFormatting((error) => {
					error.name = "MyError";
					error.message = "Error";
				}),
			);
			expect("stack" in projected).toBe(false);
		});

		it("keeps no stack when the message is rewritten to a prefix that ends mid-line", () => {
			const projected = loggableError(
				rewrittenAfterFormatting((error) => {
					error.message = "orig";
				}, "orig and more\n    at evil (S3CRET:1:1)"),
			);
			expect("stack" in projected).toBe(false);
		});

		it("keeps no stack for a message that is not a string: it has no defined header", () => {
			const error = new Error("m");
			expect(error.stack).toMatch(/^Error: m\n/);
			(error as unknown as { message: unknown }).message = 42;
			expect("stack" in loggableError(error)).toBe(false);
		});

		it("still keeps a frame-shaped line when the message is rewritten to a prefix ending at one of its own line breaks", () => {
			// The documented residual: `Error: orig` then `    at evil (…)` is
			// exactly what an error with the message `orig` looks like, so the
			// text cannot show the line is the old message's.
			const projected = loggableError(
				rewrittenAfterFormatting((error) => {
					error.message = "orig";
				}),
			);
			expect(projected.stack).toMatch(/^ {4}at evil \(S3CRET:1:1\)\n {4}at /);
		});

		/** What `fn` threw, or the error it returned. */
		const errorFrom = (fn: () => unknown): unknown => {
			try {
				return fn();
			} catch (error) {
				return error;
			}
		};

		class MyError extends Error {
			override name = "MyError";
		}

		it.each([
			["Buffer.alloc(-1)'s RangeError, its code in the header", () => Buffer.alloc(-1)],
			["new URL's TypeError", () => new URL("x")],
			["an fs ENOENT", () => readFileSync("/nonexistent/loggable-error-probe")],
			["a JSON SyntaxError", () => JSON.parse("{x")],
			[
				"an AggregateError with a message",
				() => new AggregateError([new Error("a")], "all failed"),
			],
			["an AggregateError without one", () => new AggregateError([new Error("a")])],
			[
				"a constructed DOMException TimeoutError",
				() => new DOMException("timed out", "TimeoutError"),
			],
			["a subclass that names itself", () => new MyError("boom")],
		])("keeps the frames of %s", (_label, fn) => {
			expect(loggableError(errorFrom(fn)).stack).toMatch(/^ {4}at /);
		});

		it("keeps the frames of AbortSignal.timeout's TimeoutError", async () => {
			const signal = AbortSignal.timeout(0);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(signal.aborted).toBe(true);
			expect(loggableError(signal.reason).stack).toMatch(/^ {4}at /);
		});

		/** An error with `fields` and a stack assigned by hand. */
		const handAssigned = (stack: string, fields: Record<string, unknown> = {}): Error => {
			const error = Object.assign(new Error(""), fields);
			error.stack = stack;
			return error;
		};

		it.each([
			["the name alone, as V8 writes an empty message's header", "Error\n    at a"],
			["`name: `, as source-map formatters write it", "Error: \n    at a"],
		])("keeps the frames under %s", (_label, stack) => {
			expect(loggableError(handAssigned(stack)).stack).toBe("    at a");
		});

		it("keeps the frames under `name [code]` for an empty message with a string code", () => {
			expect(loggableError(handAssigned("Error [ERR_X]\n    at a", { code: "ERR_X" })).stack).toBe(
				"    at a",
			);
		});

		it("keeps no stack under `name [code]: message` when the code is not a string", () => {
			const error = handAssigned("Error [42]: m\n    at a", { code: 42 });
			error.message = "m";
			expect("stack" in loggableError(error)).toBe(false);
		});

		it("keeps at most ten frames and 2048 characters, whichever comes first", () => {
			expect(LOGGED_STACK_MAX_FRAMES).toBe(10);
			expect(LOGGED_STACK_MAX_LENGTH).toBe(2048);
			const limit = Error.stackTraceLimit;
			Error.stackTraceLimit = 50;
			try {
				const recurse = (n: number): never => (n === 0 ? refusesTheRecord() : recurse(n - 1));
				const deep = loggableError(thrownBy(() => recurse(30)));
				expect(String(deep.stack).split("\n")).toHaveLength(10);
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

		it("keeps no stack whose read throws, and never throws itself", () => {
			const error = new Error("m");
			Object.defineProperty(error, "stack", {
				get() {
					throw new Error("getter");
				},
			});
			expect(loggableError(error)).toEqual({ name: "Error", message: "m" });
		});
	});

	it("gives every projection an own, non-enumerable `constructor: undefined`", () => {
		// pino's error serializer types an error by `constructor.name` when it
		// has a constructor, so every projection — a plain object — would log
		// as `"type": "Object"`; without one it takes `name`. pino is not a
		// dependency of this package, so the serializer itself is not run here.
		for (const projected of [loggableError(thrownBy(refusesTheRecord)), loggableError("s3cret")]) {
			expect(Object.hasOwn(projected, "constructor")).toBe(true);
			expect(projected.constructor).toBeUndefined();
			expect(Object.getOwnPropertyDescriptor(projected, "constructor")?.enumerable).toBe(false);
			expect(Object.keys(projected)).not.toContain("constructor");
			expect(JSON.stringify(projected)).not.toContain("constructor");
		}
	});

	describe("where Error.isError is missing, as on Node 22", () => {
		const isError = (Error as { isError?: unknown }).isError;
		afterEach(() => {
			if (isError !== undefined) {
				(Error as { isError?: unknown }).isError = isError;
			}
		});

		it("reports a value whose prototype cannot be read as thrown, never throwing itself", () => {
			// The `instanceof Error` fallback walks the prototype chain; a Proxy
			// whose `getPrototypeOf` trap throws turns that walk into a throw.
			delete (Error as { isError?: unknown }).isError;
			const hostile = new Proxy(
				{},
				{
					getPrototypeOf() {
						throw new Error("trap");
					},
				},
			);
			expect(loggableError(hostile)).toEqual({ thrown: "object" });
		});
	});
});
