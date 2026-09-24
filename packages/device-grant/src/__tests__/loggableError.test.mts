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
 * the rule, against the real errors it is written for.
 */

import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { LOGGED_STRING_MAX_LENGTH, loggableError } from "#/loggableError.mjs";

/**
 * redis-errors' own `ReplyError`, the class ioredis raises for a Redis error
 * reply. This package does not depend on a Redis client, so it is resolved
 * through ioredis as the sibling redis package installs it.
 */
const { ReplyError } = createRequire(
	createRequire(new URL("../../../redis/package.json", import.meta.url)).resolve("ioredis"),
)("redis-errors") as { ReplyError: new (message: string) => Error };

const parseErrorOf = (input: string): Error => {
	try {
		JSON.parse(input);
	} catch (error) {
		return error as Error;
	}
	throw new Error("parsed");
};

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
		});
	});

	it("keeps `type` only as a string, as body-parser and http-errors set it", () => {
		expect(loggableError(Object.assign(new Error("m"), { type: 42 }))).toEqual({
			name: "Error",
			message: "m",
		});
	});

	it("cuts what a real Redis ReplyError quotes of its command", () => {
		const error = new ReplyError(
			"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'",
		);
		expect(error.name).toBe("ReplyError");
		expect(loggableError(error)).toEqual({
			name: "ReplyError",
			message: "ERR unknown command 'evalsha'",
		});
	});

	it("drops a real JSON.parse SyntaxError's message, keeping the position it names", () => {
		// V8 quotes its input there; body-parser's `entity.parse.failed` is one
		// quoting the request body.
		expect(loggableError(parseErrorOf('{"user_code":"BCDFGHJK","sub":"user-1"'))).toEqual({
			name: "SyntaxError",
			position: 38,
		});
		const quoted = loggableError(parseErrorOf("user_code=BCDFGHJK&sub=user-1"));
		expect(quoted).toEqual({ name: "SyntaxError" });
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
		expect(loggableError(error)).toEqual({ name: "Error", message: "m" });
	});

	it("reports a thrown value that is not an Error by its type alone", () => {
		expect(loggableError("boom s3cret")).toEqual({ thrown: "string" });
		expect(loggableError(42)).toEqual({ thrown: "number" });
		expect(loggableError(null)).toEqual({ thrown: "object" });
		expect(loggableError({ message: "m s3cret", code: "E" })).toEqual({ thrown: "object" });
	});
});
