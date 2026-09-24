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
				error_description: "Bad Request",
				cause: { error: "invalid_grant", error_description: "Bad Request" },
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

	it("drops a field of the wrong shape rather than coercing it", () => {
		const odd = Object.assign(new Error("odd"), {
			code: { nested: "at-secret" },
			status: "400",
			error: 'not an error code, it has spaces and a "quote"',
		});
		expect(loggableError(odd)).toEqual({ name: "Error", message: "odd" });
	});

	it("says only what kind of value was thrown when it is not an Error", () => {
		expect(loggableError("at-secret")).toEqual({ name: "NonError", type: "string" });
		expect(loggableError({ access_token: "at-secret" })).toEqual({
			name: "NonError",
			type: "object",
		});
		expect(loggableError(null)).toEqual({ name: "NonError", type: "null" });
	});

	it("stops following causes after a few, so a cycle cannot recurse forever", () => {
		const a = new Error("a");
		const b = new Error("b", { cause: a });
		(a as { cause?: unknown }).cause = b;
		const projected = JSON.stringify(loggableError(a));
		expect(projected.match(/"message"/g)?.length).toBeLessThanOrEqual(4);
	});
});
