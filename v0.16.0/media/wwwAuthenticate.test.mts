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
 * The `WWW-Authenticate` reader on its own: which values carry a `Bearer`
 * challenge, and that a hostile value costs a scan, not a quadratic walk.
 * Called directly because a real server's header size limit caps the input
 * well below what the reader must be safe against; the credential suite
 * drives it through the wire.
 */

import { describe, expect, it } from "vitest";
import { hasBearerChallenge } from "#/repositories/wwwAuthenticate.mjs";

describe("hasBearerChallenge", () => {
	it("finds a Bearer auth-scheme wherever a challenge begins, in any case", () => {
		const bearer = [
			"Bearer",
			'bearer realm="x"',
			'Basic realm="x", Bearer',
			'Basic realm="x",Bearer error="invalid_token"',
			'Basic realm="x" , Bearer',
			"Bearer abc==",
			"Basic abc==, Bearer",
			"Bearer,",
			",Bearer",
			" Bearer ",
			"Bearer\t",
			'DPoP algs="ES256", Bearer realm="x"',
			"Bearer error=invalid_token",
			'Basic realm="x", foo=bar, Bearer',
			"Negotiate, BEARER",
		];
		expect(bearer.filter((value) => !hasBearerChallenge(value))).toEqual([]);
	});

	it("does not find one in a quoted string, a parameter's name, a longer word, or nothing", () => {
		const notBearer = [
			'Basic realm="Bearer"',
			'Basic realm="a\\"b, Bearer c"',
			// An unterminated quoted string runs to the end of the value: what
			// follows its opening quote is its content, not a challenge.
			'Basic realm="unterminated, Bearer',
			'"abc\\',
			"Basic realm=Bearer",
			"Basic bearer=x",
			'Basic realm="x", bearer=1',
			'Basic realm="x", bearer =1',
			'Basic realm="x", bearer  = 1',
			'Basic realm="x", bearer\t=1',
			'Basic realm="x", bearer \t= 1',
			"X, Bearer-ish",
			"Bearerish",
			'DPoP algs="ES256"',
			"",
		];
		expect(notBearer.filter((value) => hasBearerChallenge(value))).toEqual([]);
		expect(hasBearerChallenge(null)).toBe(false);
	});

	it("reads a hostile 64 KiB value in one pass — a Store's 401 cannot stall the process", () => {
		// Each of these walked quadratically in an earlier expression: an
		// unterminated quoted string of escaped quotes (the quoted-string
		// blanking retried from every quote), and `bearer` followed by a long
		// run of whitespace and then `=` (the scheme's lookahead retried from
		// every shorter run). At 64 KiB that is seconds per answer.
		const size = 64 * 1024;
		const hostile = [
			`"${'\\"'.repeat(size / 2)}`,
			`Basic x, bearer${" ".repeat(size)}=`,
			`Basic x, bearer${"\t ".repeat(size / 2)}=`,
			",".repeat(size),
			`,${" ".repeat(size)}bearex`,
		];
		for (const value of hostile) {
			const started = performance.now();
			hasBearerChallenge(value);
			expect(performance.now() - started, value.slice(0, 24)).toBeLessThan(100);
		}
	});
});
