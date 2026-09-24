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
 * What an audit event may carry of an error: its name and its code, never
 * its message. An audit sink is a record other systems read; a store's or an
 * IdP's error message is peer-written text — the command Redis refused,
 * with the token it carried; the input a JSON parser choked on; an upstream's
 * own description.
 */

import { describe, expect, it } from "vitest";
import { auditedError } from "#/audit/auditedError.mjs";

const TOKEN = "devauth:user:BCDFGHJK";

/** redis-errors' ReplyError (ioredis): the server quotes the command's arguments. */
const replyError = (): Error =>
	Object.assign(
		new Error(
			`ERR unknown command 'evalsha', with args beginning with: 'sha' '1' '${TOKEN}' 'user-1'`,
		),
		{ name: "ReplyError", command: { name: "evalsha", args: ["sha", "1", TOKEN] } },
	);

/** A store's record that did not parse: V8 quotes the start of the input. */
const parseError = (): Error => {
	try {
		JSON.parse(`${TOKEN} is not a JSON document`);
	} catch (err) {
		return err as Error;
	}
	throw new Error("JSON.parse accepted a document that is not JSON");
};

describe("auditedError", () => {
	it("keeps a Redis reply error's name and nothing it quotes", () => {
		const audited = auditedError(replyError());
		expect(audited).toEqual({ name: "ReplyError" });
		expect(JSON.stringify(audited)).not.toContain(TOKEN);
	});

	it("keeps a JSON parse error's name and none of the input it quotes", () => {
		const failure = parseError();
		expect(failure.message).toContain(TOKEN.slice(0, 10));
		const audited = auditedError(failure);
		expect(audited).toEqual({ name: "SyntaxError" });
		expect(JSON.stringify(audited)).not.toContain(TOKEN.slice(0, 10));
	});

	it("keeps a library's code, and none of an upstream's description", () => {
		// openid-client's shape: an OAuth refusal from the IdP, in its words.
		const refusal = Object.assign(new Error(`server responded with an error: ${TOKEN}`), {
			name: "ResponseBodyError",
			code: "OAUTH_RESPONSE_BODY_ERROR",
			error: "invalid_grant",
			error_description: `refresh token ${TOKEN} was revoked`,
		});
		const audited = auditedError(refusal);
		expect(audited).toEqual({ name: "ResponseBodyError", code: "OAUTH_RESPONSE_BODY_ERROR" });
		expect(JSON.stringify(audited)).not.toContain(TOKEN);
	});

	it("writes a numeric code as a string, so the field has one type in every event", () => {
		expect(auditedError(Object.assign(new Error("x"), { code: 503 }))).toEqual({
			name: "Error",
			code: "503",
		});
	});

	it("keeps one level of cause: a fetch failure's network code", () => {
		// undici's `fetch failed` is a TypeError whose cause holds what went
		// wrong: without it every unreachable host reads the same.
		const refused = Object.assign(new Error("connect ECONNREFUSED 10.0.0.5:6379"), {
			code: "ECONNREFUSED",
			errno: -61,
			syscall: "connect",
			address: "10.0.0.5",
			port: 6379,
		});
		const failed = new TypeError("fetch failed", { cause: refused });
		const audited = auditedError(failed);
		expect(audited).toEqual({
			name: "TypeError",
			cause: { name: "Error", code: "ECONNREFUSED" },
		});
		expect(JSON.stringify(audited)).not.toContain("10.0.0.5");
	});

	it("keeps no more than one level of cause", () => {
		const root = Object.assign(new Error("root"), { code: "EROOT" });
		const middle = new Error("middle", { cause: root });
		const top = new Error("top", { cause: middle });
		expect(auditedError(top)).toEqual({ name: "Error", cause: { name: "Error" } });
	});

	it("says what kind of value was thrown when it is not an Error, and nothing of it", () => {
		expect(auditedError(TOKEN)).toEqual({ name: "NonError" });
		expect(auditedError({ token: TOKEN })).toEqual({ name: "NonError" });
	});

	it("bounds a name and a code, and holds them to printable ASCII", () => {
		const odd = Object.assign(new Error("x"), {
			name: `Store—"Error"\r\n${"x".repeat(400)}`,
			code: "Eé",
		});
		const audited = auditedError(odd);
		expect(audited.name.startsWith("Store??Error???x")).toBe(true);
		expect(audited.name.length).toBeLessThanOrEqual(200);
		expect(audited.code).toBe("E?");
	});
});
