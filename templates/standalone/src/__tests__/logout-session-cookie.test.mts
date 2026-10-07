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
 * The template's two logout endpoints and the session cookie: the session
 * store module expires the cookie of a session destroyed during the request,
 * whichever route destroyed it, so `POST /oauth/logout` — whose package knows
 * no cookie name — and `POST /session/logout` both answer with the cookie
 * expired, with the attributes the login set it with.
 */

import type { SessionCookiePolicy } from "@o3co/auth-provider-core";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { authorize, codeFrom, compose, login, redeem } from "./all-modules-composition.fixture.mjs";

/** The `Set-Cookie` lines among `lines` for the cookie `name`. */
const linesNamed = (lines: readonly string[], name: string): string[] =>
	lines.filter((line) => line.startsWith(`${name}=`));

/** A response's `Set-Cookie` lines. */
const setCookies = (res: request.Response): string[] =>
	([] as string[]).concat(res.headers["set-cookie"] ?? []);

/** A `Set-Cookie` line's attributes, lower-cased, with its value and expiry left out. */
const attributesOf = (line: string): string[] =>
	line
		.split(";")
		.slice(1)
		.map((part) => part.trim().toLowerCase())
		.filter((part) => !part.startsWith("expires=") && !part.startsWith("max-age="))
		.sort();

/** The CSRF token a login reissued, read off its double-submit cookie. */
const csrfTokenOf = (cookies: readonly string[]): string => {
	const cookie = cookies.find((c) => /^[^=]*\.csrf=/.test(c));
	if (cookie === undefined) throw new Error("the login reissued no CSRF cookie");
	return decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1).split(";")[0] ?? "");
};

/**
 * The one `Set-Cookie` line of `res` for the session cookie, checked to
 * expire it with the attributes of `setLine`, the line the login set it with.
 */
function expectExpired(res: request.Response, name: string, setLine: string): void {
	const lines = linesNamed(setCookies(res), name);
	expect(lines).toHaveLength(1);
	const [line] = lines as [string];
	expect(line.startsWith(`${name}=;`)).toBe(true);
	expect(line).toContain("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
	expect(attributesOf(line)).toEqual(attributesOf(setLine));
}

describe("the session cookie at the template's logout endpoints", () => {
	it("POST /oauth/logout expires the session cookie, with the attributes the login set it with", async () => {
		const { app, handle } = await compose();
		try {
			const policy = handle.components.sessionCookiePolicy as SessionCookiePolicy;
			const { res: signedIn, cookies } = await login(app);
			expect(signedIn.status).toBe(200);
			const [setLine] = linesNamed(cookies, policy.name);
			expect(setLine).toBeDefined();
			const tokens = await redeem(app, codeFrom(await authorize(app, cookies)));
			expect(tokens.status).toBe(200);

			const res = await request(app)
				.post("/oauth/logout")
				.set("Cookie", cookies)
				.type("form")
				.send({ id_token_hint: tokens.body.id_token as string });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expectExpired(res, policy.name, setLine as string);
		} finally {
			await handle.dispose();
		}
	});

	it("POST /session/logout expires the session cookie, with the attributes the login set it with", async () => {
		const { app, handle } = await compose();
		try {
			const policy = handle.components.sessionCookiePolicy as SessionCookiePolicy;
			const { res: signedIn, cookies } = await login(app);
			expect(signedIn.status).toBe(200);
			const [setLine] = linesNamed(cookies, policy.name);
			expect(setLine).toBeDefined();

			const res = await request(app)
				.post("/session/logout")
				.set("Cookie", cookies)
				.set("x-csrf-token", csrfTokenOf(cookies));

			expect(res.status).toBe(200);
			expectExpired(res, policy.name, setLine as string);
		} finally {
			await handle.dispose();
		}
	});
});
