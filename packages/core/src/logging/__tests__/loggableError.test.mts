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

import { inspect } from "node:util";
import { runInNewContext } from "node:vm";
import express from "express";
import * as yaml from "js-yaml";
import pino from "pino";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
	guardedRead,
	LOGGED_AGGREGATE_MAX_ERRORS,
	LOGGED_MAX_PROJECTIONS,
	LOGGED_PRINT_DEPTH,
	LOGGED_STACK_MAX_FRAMES,
	LOGGED_STACK_MAX_LENGTH,
	type LoggableError,
	loggableError,
	uncappedDetail,
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
		const { stack: _frames, cause, aggregateErrors, ...fields } = projected;
		return {
			...fields,
			...(cause === undefined ? {} : { cause: walk(cause) }),
			...(aggregateErrors === undefined ? {} : { aggregateErrors: aggregateErrors.map(walk) }),
		};
	};
	return walk(loggableError(err));
};

describe("loggableError — what a log line may carry of an error", () => {
	it("keeps name, message (as `detail`) and code, and the chain of Error causes", () => {
		expect(shape(libraryError())).toEqual({
			name: "ClientError",
			detail: "invalid response encountered",
			code: "OAUTH_INVALID_RESPONSE",
			cause: {
				name: "OperationProcessingError",
				detail: '"response" body "scope" property must be a string',
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
			detail: "server responded with an error in the response body",
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
		expect(shape(odd)).toEqual({ name: "Error", detail: "odd" });
	});

	it("says only what kind of value was thrown when it is not an Error — in `thrown`", () => {
		expect(shape("at-secret")).toEqual({ name: "NonError", thrown: "string" });
		expect(shape({ access_token: "at-secret" })).toEqual({
			name: "NonError",
			thrown: "object",
		});
		expect(shape(null)).toEqual({ name: "NonError", thrown: "null" });
	});

	it("marks a cause the depth limit leaves out, as it marks one the budget does", () => {
		let chain: Error = new Error("c5");
		for (let level = 4; level >= 0; level--) chain = new Error(`c${level}`, { cause: chain });
		let last: LoggableError | undefined = loggableError(chain);
		for (let level = 0; level < 3; level++) last = last?.cause;
		// c0, and three causes below it: c3 is the last, and it says it had one.
		expect(last?.detail).toBe("c3");
		expect(last?.cause).toBeUndefined();
		expect(last?.causeOmitted).toBe(true);
	});

	it("stops following causes after a few, so a cycle cannot recurse forever", () => {
		const a = new Error("a");
		const b = new Error("b", { cause: a });
		(a as { cause?: unknown }).cause = b;
		const projected = JSON.stringify(loggableError(a));
		expect(projected.match(/"detail"/g)?.length).toBeLessThanOrEqual(4);
	});

	describe("an AggregateError's members", () => {
		/** What an OAuth library throws for a refresh answer it refused: the answer on a non-Error cause. */
		const refusedRefresh = (): Error =>
			Object.assign(
				new Error("invalid response encountered", {
					cause: { body: { refresh_token: "rt-MEMBER-S3CRET" } },
				}),
				{ name: "ClientError", code: "OAUTH_INVALID_RESPONSE" },
			);

		it("keeps its Error members, each projected as a cause is — names and codes, never what they carry", () => {
			const reply = Object.assign(
				new Error(
					"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'fg:grant:rt-ARG-S3CRET'",
				),
				{ name: "ReplyError", command: { name: "evalsha", args: ["fg:grant:rt-ARG-S3CRET"] } },
			);
			const failed = new AggregateError(
				[refusedRefresh(), reply],
				"AppHandle.dispose: 2 cleanup errors",
			);

			expect(shape(failed)).toEqual({
				name: "AggregateError",
				detail: "AppHandle.dispose: 2 cleanup errors",
				aggregateErrors: [
					{
						name: "ClientError",
						detail: "invalid response encountered",
						code: "OAUTH_INVALID_RESPONSE",
					},
					{
						name: "ReplyError",
						detail: "ERR unknown command 'evalsha'",
						command: { name: "evalsha" },
					},
				],
			});
			const projected = loggableError(failed);
			expect(projected.aggregateErrors?.[0]?.stack).toMatch(/^ {4}at /);
			const serialised = JSON.stringify(projected);
			expect(serialised).not.toContain("S3CRET");
			expect(serialised).not.toContain("refresh_token");
		});

		it(`keeps at most the first ${LOGGED_AGGREGATE_MAX_ERRORS}, and says how many it left out`, () => {
			expect(LOGGED_AGGREGATE_MAX_ERRORS).toBe(5);
			const many = new AggregateError(
				Array.from({ length: 7 }, (_, i) => Object.assign(new Error(`m${i}`), { name: `E${i}` })),
				"all failed",
			);
			const projected = loggableError(many);
			expect(projected.aggregateErrors?.map((member) => member.name)).toEqual([
				"E0",
				"E1",
				"E2",
				"E3",
				"E4",
			]);
			expect(projected.aggregateErrorsOmitted).toBe(2);
		});

		it("leaves out a member that is not an Error, as it does a cause, and counts it", () => {
			const mixed = new AggregateError(
				["rt-STRING-S3CRET", { access_token: "at-OBJECT-S3CRET" }, new TypeError("kept")],
				"mixed",
			);
			expect(shape(mixed)).toEqual({
				name: "AggregateError",
				detail: "mixed",
				aggregateErrors: [{ name: "TypeError", detail: "kept" }],
				aggregateErrorsOmitted: 2,
			});
			expect(JSON.stringify(loggableError(mixed))).not.toContain("S3CRET");
		});

		it("keeps no members field when none of them is an Error — a validation library's issues", () => {
			const issues = Object.assign(new Error("invalid input"), {
				name: "ZodError",
				errors: [{ path: ["client_secret"], message: "s3cret-value is too short" }],
			});
			expect(shape(issues)).toEqual({ name: "ZodError", detail: "invalid input" });
		});

		it("follows members as deep as causes, and no deeper", () => {
			let nested: Error = new Error("innermost");
			for (let level = 4; level >= 0; level--) {
				nested = new AggregateError([nested], `level ${level}`);
			}
			const depthOf = (projected: LoggableError | undefined): number =>
				projected === undefined ? 0 : 1 + depthOf(projected.aggregateErrors?.[0]);
			// The error and three levels below it, as with causes.
			expect(depthOf(loggableError(nested))).toBe(4);
		});

		it("says what the depth limit left out: the last level's members in `aggregateErrorsOmitted`", () => {
			let nested: Error = new Error("innermost");
			for (let level = 4; level >= 0; level--) {
				nested = new AggregateError([nested, new Error(`sibling ${level}`)], `level ${level}`);
			}
			let last: LoggableError | undefined = loggableError(nested);
			for (let level = 0; level < 3; level++) last = last?.aggregateErrors?.[0];
			expect(last?.detail).toBe("level 3");
			expect(last?.aggregateErrors).toBeUndefined();
			expect(last?.aggregateErrorsOmitted).toBe(2);
		});

		it("never throws on an `errors` that cannot be read", () => {
			const unreadable = Object.defineProperty(new AggregateError([], "outer"), "errors", {
				get() {
					throw new Error("getter");
				},
			});
			expect(shape(unreadable)).toEqual({ name: "AggregateError", detail: "outer" });
			const trap = () => {
				throw new Error("trap");
			};
			const hostile = Object.assign(new Error("outer"), {
				errors: new Proxy([new Error("m")], { get: trap, getPrototypeOf: trap }),
			});
			expect(() => loggableError(hostile)).not.toThrow();
			const revocable = Proxy.revocable([new Error("m")], {});
			revocable.revoke();
			const revoked = Object.assign(new Error("outer"), { errors: revocable.proxy });
			expect(shape(revoked)).toEqual({ name: "Error", detail: "outer" });
		});

		it.each([
			["a string", "1"],
			["a fraction", 1.5],
			["a negative count", -1],
			["NaN", Number.NaN],
		])("keeps no members of an `errors` array whose `length` reads as %s", (_label, length) => {
			// Array.isArray says yes to a Proxy over an array, whose `length`
			// can then answer anything; only a count is one.
			const lying = new Proxy([new Error("member")], {
				get: (target, key) => (key === "length" ? length : Reflect.get(target, key)),
			});
			const outer = Object.assign(new Error("outer"), { errors: lying });
			expect(shape(outer)).toEqual({ name: "Error", detail: "outer" });
		});
	});

	describe("a budget for one line", () => {
		/**
		 * An error `levels` deep whose every level has five Error members and
		 * an Error cause, each with a long message: past the depth limit, 259
		 * projections without a budget.
		 */
		const tree = (levels: number, label = "root"): Error => {
			const long = `${label} ${"x".repeat(1000)}`;
			if (levels === 0) return new Error(long);
			return new AggregateError(
				Array.from({ length: 5 }, (_, i) => tree(levels - 1, `${label}.${i}`)),
				long,
				{ cause: tree(levels - 1, `${label}.cause`) },
			);
		};
		/** How many projections a line holds: the error, and its causes and members, all the way down. */
		const count = (projected: LoggableError | undefined): number =>
			projected === undefined
				? 0
				: 1 +
					count(projected.cause) +
					(projected.aggregateErrors ?? []).reduce((sum, member) => sum + count(member), 0);
		const labelOf = (projected: LoggableError | undefined): string | undefined =>
			projected?.detail?.split(" ")[0];

		it(`keeps at most ${LOGGED_MAX_PROJECTIONS} projections in one line, the nearest first`, () => {
			expect(LOGGED_MAX_PROJECTIONS).toBe(16);
			const projected = loggableError(tree(4));
			expect(count(projected)).toBe(LOGGED_MAX_PROJECTIONS);
			// Sixteen, each capped: a line a log shipper takes whole.
			expect(JSON.stringify(projected).length).toBeLessThan(LOGGED_MAX_PROJECTIONS * 4096);
			// The error's own cause and all five of its members come before
			// anything of theirs.
			expect(labelOf(projected.cause)).toBe("root.cause");
			expect(projected.aggregateErrors?.map(labelOf)).toEqual([
				"root.0",
				"root.1",
				"root.2",
				"root.3",
				"root.4",
			]);
			expect(projected.aggregateErrorsOmitted).toBeUndefined();
		});

		it("says what the budget left out: a member in `aggregateErrorsOmitted`, a cause as `causeOmitted`", () => {
			const projected = loggableError(tree(4));
			const first = projected.aggregateErrors?.[0];
			expect(labelOf(first?.cause)).toBe("root.0.cause");
			expect(first?.aggregateErrors?.map(labelOf)).toEqual(["root.0.0", "root.0.1"]);
			expect(first?.aggregateErrorsOmitted).toBe(3);
			const last = projected.aggregateErrors?.[4];
			expect(last?.cause).toBeUndefined();
			expect(last?.causeOmitted).toBe(true);
			expect(last?.aggregateErrors).toBeUndefined();
			expect(last?.aggregateErrorsOmitted).toBe(5);
		});
	});

	describe("the command a store's error answered", () => {
		it("keeps the name of ioredis's `command`, and never its arguments", () => {
			const refused = Object.assign(new Error("WRONGPASS invalid username-password pair"), {
				name: "ReplyError",
				command: { name: "hello", args: ["3", "AUTH", "default", "pw-S3CRET"] },
			});
			expect(shape(refused)).toEqual({
				name: "ReplyError",
				detail: "WRONGPASS invalid username-password pair",
				command: { name: "hello" },
			});
			expect(JSON.stringify(loggableError(refused))).not.toContain("S3CRET");
		});

		it.each([["JSON.SET"], ["FT.SEARCH"], ["json.get"]])(
			"keeps a Redis module command's dotted name: %s",
			(name) => {
				const refused = Object.assign(new Error("ERR could not perform this operation"), {
					name: "ReplyError",
					command: { name, args: ["doc:S3CRET", "$", "{}"] },
				});
				expect(loggableError(refused).command).toEqual({ name });
				expect(JSON.stringify(loggableError(refused))).not.toContain("S3CRET");
			},
		);

		it.each([
			["a shell command line, as execa carries it", "git push https://token-S3CRET@example.com"],
			["a name with a space", { name: "set key-S3CRET" }],
			["a name with two dots", { name: "a.b.c" }],
			["a dotted name with a space", { name: "JSON.SET key-S3CRET" }],
			["a name that ends in a dot", { name: "JSON." }],
			["an over-long name", { name: "x".repeat(33) }],
			["a name that is not a string", { name: 42 }],
			["no name", { args: ["S3CRET"] }],
		])("drops a `command` that is %s", (_label, command) => {
			const projected = loggableError(Object.assign(new Error("m"), { command }));
			expect(projected).not.toHaveProperty("command");
			expect(JSON.stringify(projected)).not.toContain("S3CRET");
		});

		it("never throws on a `command` whose name cannot be read", () => {
			const command = Object.defineProperty({}, "name", {
				get() {
					throw new Error("getter");
				},
			});
			expect(shape(Object.assign(new Error("m"), { command }))).toEqual({
				name: "Error",
				detail: "m",
			});
		});
	});

	describe("a closed-set field a store's error records", () => {
		it.each([["unreachable"], ["connection_closed"], ["malformed_response"], ["expired-at-issue"]])(
			"keeps an own `reason` that is a code: %j",
			(reason) => {
				expect(shape(Object.assign(new Error("m"), { reason }))).toEqual({
					name: "Error",
					detail: "m",
					reason,
				});
			},
		);

		it.each([
			["free text", "Token has been expired or revoked."],
			["a camel-cased word", "keyCompromise"],
			["a lowercase hex token", "a3f9c0e1d2b4a6f8c0e1d2b4a6f8c0e1"],
			["a UUID", "f47ac10b-58cc-4372-a567-0e02b2c3d479"],
			["an over-long code", `${"a_".repeat(40)}b`],
			["a number", 42],
		])("drops a `reason` that is %s", (_label, reason) => {
			expect(shape(Object.assign(new Error("m"), { reason }))).toEqual({
				name: "Error",
				detail: "m",
			});
		});

		it("drops a `reason` the error inherits rather than owns", () => {
			class Inherited extends Error {}
			Object.defineProperty(Inherited.prototype, "reason", { value: "unreachable" });
			expect(shape(new Inherited("m"))).toEqual({ name: "Error", detail: "m" });
		});

		it("keeps an own `…Status` field that holds an HTTP status — an upstream's answer beside the error's own `status`", () => {
			const refused = Object.assign(new Error("the Store refused this deployment's credential"), {
				name: "StoreCredentialRefusedError",
				storeStatus: 401,
				upstreamStatus: 503,
			});
			expect(shape(refused)).toEqual({
				name: "StoreCredentialRefusedError",
				detail: "the Store refused this deployment's credential",
				storeStatus: 401,
				upstreamStatus: 503,
			});
		});

		it.each([
			["below the HTTP range", { storeStatus: 99 }],
			["above it", { storeStatus: 600 }],
			["fractional", { storeStatus: 401.5 }],
			["a string", { storeStatus: "401" }],
			[
				"under a name that is not `<word>Status`",
				{ store_status: 401, Status: 401, storestatus: 401 },
			],
		])("drops a status field %s", (_label, fields) => {
			expect(shape(Object.assign(new Error("m"), fields))).toEqual({ name: "Error", detail: "m" });
		});

		it("keeps at most four `…Status` fields", () => {
			const many = Object.assign(new Error("m"), {
				aStatus: 401,
				bStatus: 402,
				cStatus: 403,
				dStatus: 404,
				eStatus: 405,
			});
			expect(Object.keys(loggableError(many)).filter((key) => key.endsWith("Status"))).toEqual([
				"aStatus",
				"bStatus",
				"cStatus",
				"dStatus",
			]);
		});

		it("never throws on an error whose own keys cannot be listed, and keeps what it can read", () => {
			// A Proxy over an Error whose own-key traps throw: `reason`'s
			// own-ness and the `<word>Status` fields' listing both ask them.
			// Where the runtime has Error.isError (Node 24+) a Proxy is not an
			// Error and projects as a NonError; on Node 22, the engines floor,
			// the fallback's `instanceof` counts it, and the projection reaches
			// those questions.
			const trap = () => {
				throw new Error("trap");
			};
			const hostile = () =>
				new Proxy(Object.assign(new Error("m"), { reason: "unreachable", storeStatus: 503 }), {
					ownKeys: trap,
					getOwnPropertyDescriptor: trap,
				});
			expect(() => loggableError(hostile())).not.toThrow();
			const brand = Object.getOwnPropertyDescriptor(Error, "isError");
			delete (Error as { isError?: unknown }).isError;
			try {
				const projected = loggableError(hostile());
				expect(projected).toMatchObject({ name: "Error", detail: "m" });
				expect(projected).not.toHaveProperty("reason");
				expect(projected).not.toHaveProperty("storeStatus");
			} finally {
				if (brand) Object.defineProperty(Error, "isError", brand);
			}
		});
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

		it("keeps a message whole for uncappedDetail, but on one line", () => {
			// A boot failure's message carries it: uncapped, so a refusal's advice
			// survives; filtered as every kept string is, so it cannot forge a line.
			const long = `first line\nforged: line \u202etxt.exe ${"x".repeat(300)}`;
			expect(uncappedDetail(new RangeError(long))).toBe(
				`first line?forged: line ?txt.exe ${"x".repeat(300)}`,
			);
		});

		it("drops a YAMLException's message, which quotes the lines around the fault", () => {
			// js-yaml writes a snippet of the neighbouring lines into the message
			// (and keeps the whole input on `mark.buffer`, which is never read):
			// a clients file parsed by a host's own module carries its secrets.
			let failed: unknown;
			try {
				yaml.load("web:\n  clientSecret: yaml-secret-marker\n  bad\nnext: 1\n");
			} catch (err) {
				failed = err;
			}
			expect(failed).toBeInstanceOf(yaml.YAMLException);
			expect(shape(failed)).toEqual({ name: "YAMLException" });
			expect(uncappedDetail(failed)).toBeUndefined();
			expect(JSON.stringify(loggableError(failed))).not.toContain("yaml-secret-marker");
			expect(inspect(loggableError(failed), { depth: Number.POSITIVE_INFINITY })).not.toContain(
				"yaml-secret-marker",
			);
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
				detail: "ERR unknown command 'evalsha'",
				command: { name: "evalsha" },
			});
			expect(JSON.stringify(loggableError(reply))).not.toContain("user-1");
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
					detail: "ERR unknown command 'evalsha'",
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
			detail: "unexpected HTTP response status code",
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

	it("reads a Response structurally, and keeps of it only what it can read", () => {
		const onCause = (cause: unknown) =>
			loggableError(new Error("unexpected HTTP response status code", { cause })).response;
		// A Response without a content type: the status alone.
		expect(onCause(new Response(null, { status: 503 }))).toEqual({ status: 503 });
		// Not a Response: headers that are not an object, or have no `get`.
		expect(onCause({ status: 503, headers: "text/html" })).toBeUndefined();
		expect(onCause({ status: 503, headers: {} })).toBeUndefined();
		// A `get` that throws: the status, and no content type.
		expect(
			onCause({
				status: 503,
				headers: {
					get() {
						throw new Error("headers trap");
					},
				},
			}),
		).toEqual({ status: 503 });
	});

	it("caps every string it keeps at 256 characters", () => {
		const long = Object.assign(new Error("m".repeat(1000)), {
			name: "N".repeat(1000),
			code: "C".repeat(1000),
			type: "t".repeat(1000),
		});
		const projected = loggableError(long);
		expect(projected.detail).toHaveLength(256);
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
			// And the fallback still counts a real error, one from another realm
			// by its tag, and neither null nor an object tagged otherwise.
			expect(shape(new Error("kept"))).toEqual({ name: "Error", detail: "kept" });
			expect(shape(runInNewContext('new TypeError("other realm")'))).toEqual({
				name: "TypeError",
				detail: "other realm",
			});
			expect(shape(null)).toEqual({ name: "NonError", thrown: "null" });
			expect(shape({ name: "Error", message: "shaped like one" })).toEqual({
				name: "NonError",
				thrown: "object",
			});
		} finally {
			if (brand) Object.defineProperty(Error, "isError", brand);
		}
	});

	/*
	 * The `stack` vectors, against errors Node and V8 really throw and stacks
	 * assigned by hand. Each needs only `loggableError`, the helpers inside
	 * this block and Node's own globals and built-ins.
	 */
	describe("stack — the vectors", () => {
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

		it("AbortSignal.timeout's TimeoutError: its frames, and not its header", async () => {
			const signal = AbortSignal.timeout(0);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(signal.aborted).toBe(true);
			const stack = stackOf(signal.reason);
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toContain("TimeoutError");
		});

		it("a subclass that names itself: its frames, and not its header", () => {
			class MyError extends Error {
				override name = "MyError";
			}
			const stack = stackOf(
				thrownBy(() => {
					throw new MyError("boom");
				}),
			);
			expect(stack).toMatch(/^ {4}at /);
			expect(stack).not.toContain("MyError");
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
			expect(loggableError(hostile).detail).toBe("kept");
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
		expect(LOGGED_PRINT_DEPTH).toBe(8);
		expect(LOGGED_AGGREGATE_MAX_ERRORS).toBe(5);
		expect(LOGGED_MAX_PROJECTIONS).toBe(16);
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

	it("carries its deep printing as a brand nothing but `util.inspect` sees", () => {
		const projected = loggableError(
			new AggregateError([new Error("member")], "outer", { cause: new Error("inner") }),
		);
		for (const level of [projected, projected.cause, projected.aggregateErrors?.[0]]) {
			const brand = Object.getOwnPropertyDescriptor(level, inspect.custom);
			expect(typeof brand?.value).toBe("function");
			expect(brand?.enumerable).toBe(false);
		}
		expect(Object.keys(projected)).not.toContain(String(inspect.custom));
		expect(JSON.stringify(projected)).toBe(JSON.stringify(JSON.parse(JSON.stringify(projected))));
		expect(JSON.stringify(projected)).not.toMatch(/inspect|nodejs\.util/);
		expect(inspect({ at: { depth: { two: projected } } })).toContain("inner");
	});

	it("is plain data with no `message`, which a serializer would take for an Error's", () => {
		const projected = loggableError(new Error("kept", { cause: new Error("inner") }));
		expect(Object.getPrototypeOf(projected)).toBe(Object.prototype);
		expect(projected).toStrictEqual(JSON.parse(JSON.stringify(projected)));
		expect(projected).not.toHaveProperty("message");
		expect(projected.cause).not.toHaveProperty("message");
	});

	describe("under pino, the line is the projection — every field, every level", () => {
		/**
		 * A request failure caused by a Store failure caused by a parse
		 * failure: the fields at each level that pino's err serializer drops
		 * when it takes the projection for an Error — it folds a `cause` into
		 * the outer message and stack and writes none of its fields, and it
		 * writes the error's name over the projection's own `type`.
		 */
		const layered = (): Error => {
			let parse: unknown;
			try {
				JSON.parse('{"a":1,');
			} catch (err) {
				parse = err;
			}
			const store = Object.assign(new Error("the Store could not be read", { cause: parse }), {
				name: "StoreTransportError",
				code: "ECONNREFUSED",
				reason: "unreachable",
				storeStatus: 503,
			});
			return Object.assign(new Error("request failed", { cause: store }), {
				type: "upstream.failed",
				status: 502,
			});
		};

		/** The `err` of the one line pino wrote for `{ err: projected }`, parsed. */
		const loggedBy = (options: pino.LoggerOptions, projected: LoggableError): unknown => {
			const lines: string[] = [];
			const log = pino(
				{ base: null, timestamp: false, ...options },
				{
					write(line: string) {
						lines.push(line);
					},
				},
			);
			log.error({ err: projected }, "failed");
			return (JSON.parse(lines[0] ?? "{}") as { err: unknown }).err;
		};

		it.each([
			["pino's default serializers", {}],
			[
				"an explicit `err: stdSerializers.err`, as the standalone template sets it",
				{
					serializers: { err: pino.stdSerializers.err },
				},
			],
			["`errWithCause`", { serializers: { err: pino.stdSerializers.errWithCause } }],
		] as const)("with %s", (_label, options) => {
			const projected = loggableError(layered());
			const err = loggedBy(options, projected);
			// Exactly the projection's own JSON: nothing dropped, nothing added —
			// the inspect brand included, which pino never writes.
			expect(err).toEqual(JSON.parse(JSON.stringify(projected)));
			expect(JSON.stringify(err)).not.toMatch(/inspect|nodejs\.util/);
			expect(err).toMatchObject({
				type: "upstream.failed",
				status: 502,
				cause: {
					name: "StoreTransportError",
					code: "ECONNREFUSED",
					reason: "unreachable",
					storeStatus: 503,
					cause: { name: "SyntaxError", position: 7 },
				},
			});
		});
	});

	it("reaches pino as it is: its `name`, its frames for `stack`, and no `type` of pino's", () => {
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
		expect(err.name).toBe("TypeError");
		expect(err).not.toHaveProperty("type");
		expect(err.stack).toMatch(/^ {4}at /);
		// The message is this process's own text here, and kept; the stack
		// carries none of it.
		expect(err.stack).not.toContain("STACKSECRET");
	});

	it("reaches pino with an AggregateError's members once, as `aggregateErrors`", () => {
		// `aggregateErrors` is the name pino writes a raw AggregateError's
		// members under; the projection's pass through as they are, once.
		const lines: string[] = [];
		const log = pino(
			{ base: null, timestamp: false },
			{
				write(line: string) {
					lines.push(line);
				},
			},
		);
		log.error(
			{ err: loggableError(new AggregateError([new TypeError("kept")], "all failed")) },
			"failed",
		);
		const { err } = JSON.parse(lines[0] ?? "{}") as { err: Record<string, unknown> };
		expect(err.aggregateErrors).toEqual([
			expect.objectContaining({ name: "TypeError", detail: "kept" }),
		]);
		expect(err).not.toHaveProperty("errors");
	});

	it("counts an error from another realm as an error", () => {
		const foreign = runInNewContext('Object.assign(new Error("from a vm"), { code: "E_VM" })');
		expect(foreign instanceof Error).toBe(false);
		expect(shape(foreign)).toEqual({ name: "Error", detail: "from a vm", code: "E_VM" });
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
		expect(shape(hostile)).toEqual({ name: "Error", detail: "kept" });
	});
});

describe("loggableError — detail is one line of text", () => {
	// A message is often a peer's or a caller's text a library quoted: jose's
	// "Extension Header Parameter \"<name>\" is not recognized", an IdP's
	// refusal, a fetch cause. Whatever breaks a line or reorders it on screen
	// is replaced by `?`: C0 (line breaks, tab, ESC), DEL, C1 (NEL, CSI), the
	// Unicode line and paragraph separators, and the bidi embedding, override
	// and isolate controls. Not RFC 6749's set: `"` and `\` stay, and so does
	// any other character, a non-ASCII letter included.
	const UNSAFE =
		"\r\n\t\u0000\u001b\u007f\u0080\u0085\u009b\u009f\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";

	it("replaces each line-breaking or reordering character with ?", () => {
		expect(loggableError(new Error(`a${UNSAFE}b`)).detail).toBe(`a${"?".repeat(UNSAFE.length)}b`);
	});

	it('keeps " and \\ and every other character', () => {
		const message = 'refused "x" at C:\\path — é 日本 ☃ \u00a0 \u200b';
		expect(loggableError(new Error(message)).detail).toBe(message);
	});

	it("still caps the detail at 256 characters", () => {
		const detail = loggableError(new Error(`\u2028${"x".repeat(10_000)}`)).detail ?? "";
		expect({ length: detail.length, head: detail.slice(0, 2) }).toEqual({
			length: 256,
			head: "?x",
		});
	});

	it("filters a cause's detail the same way", () => {
		const err = new Error("outer", { cause: new Error("in\r\nner\u202e") });
		expect(loggableError(err).cause?.detail).toBe("in??ner?");
	});

	it("replaces the directional marks U+200E, U+200F and U+061C", () => {
		expect(loggableError(new Error("a\u200eb\u200fc\u061cd")).detail).toBe("a?b?c?d");
	});

	it("never cuts the 256-character detail through a surrogate pair", () => {
		const detail = loggableError(new Error(`${"a".repeat(255)}😀`)).detail ?? "";
		expect({
			loneHigh: /[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(detail),
			length: detail.length,
		}).toEqual({ loneHigh: false, length: 255 });
	});
});

describe("loggableError — name, code and type are one line of text too", () => {
	const UNSAFE = "\r\n\u0085\u2028\u202e\u200e";

	it("replaces each line-breaking or reordering character in them with ?", () => {
		const err = Object.assign(new Error("m"), {
			code: `E${UNSAFE}CODE`,
			type: `entity${UNSAFE}type`,
		});
		err.name = `Custom${UNSAFE}Error`;
		const projected = loggableError(err);
		expect({ name: projected.name, code: projected.code, type: projected.type }).toEqual({
			name: "Custom??????Error",
			code: "E??????CODE",
			type: "entity??????type",
		});
	});
});
