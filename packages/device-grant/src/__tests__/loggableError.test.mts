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
 * What of an error a log line may carry. The mounted routes' tests pin that
 * the routes use this; these pin what it keeps and what it cuts.
 */

import { describe, expect, it } from "vitest";
import { LOGGED_FIELD_MAX_LENGTH, loggableError, redactErrorMessage } from "#/loggableError.mjs";

const parseErrorOf = (input: string): Error => {
	try {
		JSON.parse(input);
	} catch (error) {
		return error as Error;
	}
	throw new Error("parsed");
};

describe("redactErrorMessage", () => {
	it("cuts the arguments a Redis unknown-command reply quotes", () => {
		expect(
			redactErrorMessage(
				"ReplyError",
				"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'",
			),
		).toBe("ERR unknown command 'evalsha'");
	});

	it.each([
		["a token snippet", "user_code=BCDFGHJK&sub=user-1"],
		["a whole value", "[object Object]"],
		["input containing quotes", '{"user_code":BCDFGHJK}'],
	])("replaces the input V8 quotes in a JSON SyntaxError (%s)", (_label, input) => {
		const error = parseErrorOf(input);
		const redacted = redactErrorMessage(error.name, error.message);
		expect(redacted).not.toContain("BCDFGHJK");
		expect(redacted).not.toContain("user_code");
		expect(redacted).not.toContain("object Object");
		if (error.message.includes('"')) expect(redacted).toContain("<input>");
	});

	it("leaves a SyntaxError that quotes nothing as it is", () => {
		const error = parseErrorOf('{"a":1');
		expect(redactErrorMessage(error.name, error.message)).toBe(error.message);
	});

	it("leaves quotes in other errors alone", () => {
		expect(
			redactErrorMessage("TypeError", 'Cannot read properties of undefined (reading "x")'),
		).toBe('Cannot read properties of undefined (reading "x")');
	});

	it("caps what is left", () => {
		const redacted = redactErrorMessage("Error", "x".repeat(1000));
		expect(redacted).toHaveLength(LOGGED_FIELD_MAX_LENGTH);
		expect(redacted.endsWith("…")).toBe(true);
	});
});

describe("loggableError", () => {
	it("keeps name, message, type, code and status — nothing else, nothing nested", () => {
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

	it("drops a field that is not a string or a number", () => {
		expect(loggableError({ message: "m", code: { secret: "s3cret" }, status: "500" })).toEqual({
			message: "m",
			status: "500",
		});
	});

	it("reports a thrown value that is not an object by its type alone", () => {
		expect(loggableError("boom s3cret")).toEqual({ thrown: "string" });
		expect(loggableError(42)).toEqual({ thrown: "number" });
		expect(loggableError(null)).toEqual({ thrown: "object" });
	});
});
