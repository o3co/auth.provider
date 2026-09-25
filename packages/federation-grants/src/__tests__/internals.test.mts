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
 * The exits a request cannot reach through the chain (#593).
 *
 * Each of these is a composition or programming fault rather than something a
 * caller can do: a handler mounted by hand without the authentication in front
 * of it, a body-parser error that only a chunked request produces, a
 * dependency that throws where nothing is supposed to. They still decide what
 * a caller is told, and what an operator is told, so they are driven directly
 * rather than left to be discovered in production.
 */

import type { FederationGrantConnection, FederationGrantStore } from "@o3co/auth-provider-core";
import { resolveFederationGrantRetrievalLimits } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { createFederationGrantBackground } from "#/background.mjs";
import { createRouteDenialAudit } from "#/denialAudit.mjs";
import { parserRefusals, unexpectedErrors } from "#/routes.mjs";
import { createFederationGrantStatusHandler } from "#/statusRoute.mjs";
import { createFederationGrantTokenHandler } from "#/tokenRoute.mjs";

/** Just enough of a response to see what a handler decided. */
const fakeResponse = () => {
	const state = { status: 0, body: undefined as unknown, headers: {} as Record<string, string> };
	const res = {
		status(code: number) {
			state.status = code;
			return res;
		},
		json(value: unknown) {
			state.body = value;
			return res;
		},
		set(name: string, value: string) {
			state.headers[name] = value;
			return res;
		},
		getHeader: (name: string) => state.headers[name],
		on: () => res,
	};
	return { res: res as unknown as Response, state };
};

const fakeRequest = (over: Partial<Request> = {}): Request =>
	({
		params: { grantId: "g-1" },
		headers: {},
		body: { sub: "local-subject" },
		get: () => undefined,
		...over,
	}) as unknown as Request;

/** A connections map whose lookup throws, which nothing in the chain expects. */
const throwingConnections = {
	get() {
		throw new Error("the connection map exploded");
	},
} as unknown as ReadonlyMap<string, FederationGrantConnection>;

const options = (connections: ReadonlyMap<string, FederationGrantConnection>) => ({
	store: {} as FederationGrantStore,
	connections,
	refresher: () => undefined,
	grantsBoundary: async () => null,
	limits: resolveFederationGrantRetrievalLimits({ federationGrants: {} }),
	background: createFederationGrantBackground(),
	now: () => new Date(),
});

describe("a handler mounted without the authentication in front of it", () => {
	it("answers 500 on the token route rather than as if the caller were anonymous", async () => {
		// `allowedConnections: []` would be an answer about the grant. There is
		// no caller here at all, and the composition is what is wrong.
		const { res, state } = fakeResponse();
		await createFederationGrantTokenHandler(options(new Map()))(
			fakeRequest(),
			res,
			() => undefined,
		);
		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error" });
	});

	it("answers 500 on the status route for the same reason", async () => {
		const { res, state } = fakeResponse();
		await createFederationGrantStatusHandler(options(new Map()))(
			fakeRequest(),
			res,
			() => undefined,
		);
		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error" });
	});
});

describe("a dependency that throws where nothing expects one to", () => {
	const authenticated = fakeRequest({
		// biome-ignore lint/suspicious/noExplicitAny: the middleware's own augmentation
		oauthClient: { clientId: "worker", allowedFederationGrantConnections: ["calendar"] } as any,
	});

	it("is still a typed answer on the token route, because core concludes anyway", async () => {
		// Worth writing down rather than assuming: core turns EVERY cause it
		// meets into one of D11's results, including a connection lookup that
		// throws and a clock that does. So the token handler's own `catch` is a
		// guard against that contract changing, not a path a caller can take —
		// which is why it has no test of its own and this does instead.
		for (const broken of [
			{ ...options(throwingConnections) },
			{
				...options(new Map()),
				now: () => {
					throw new Error("the clock exploded");
				},
			},
		]) {
			const { res, state } = fakeResponse();
			await createFederationGrantTokenHandler(broken)(authenticated, res, () => undefined);
			expect(state.status).toBe(503);
			expect(state.body).toMatchObject({ error: "temporarily_unavailable" });
			expect(JSON.stringify(state.body)).not.toContain("exploded");
		}
	});

	it("is a 500 on the status route", async () => {
		const { res, state } = fakeResponse();
		await createFederationGrantStatusHandler({
			...options(throwingConnections),
			store: {
				inspect: async () => ({
					grant: {
						id: "g-1",
						subject: "local-subject",
						clientId: "worker",
						connection: "calendar",
						status: "active",
					},
					credentials: "ok",
				}),
			} as unknown as FederationGrantStore,
		})(authenticated, res, () => undefined);

		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error" });
	});
});

describe("what the body parsers reject, and what escapes every handler", () => {
	const logger = () => ({
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	});
	/**
	 * The two error handlers as the router chains them: the parsers' refusals
	 * right after the parsers, then — for whatever they pass on — the last
	 * handler.
	 */
	const run = (error: unknown, headersSent = false, log = logger()) => {
		const { res, state } = fakeResponse();
		(res as unknown as { headersSent: boolean }).headersSent = headersSent;
		const next = vi.fn();
		parserRefusals(error, {} as Request, res, (passed?: unknown) => {
			unexpectedErrors(log as never, "federation_grants")(passed, {} as Request, res, next);
		});
		return { state, next, log };
	};
	/** The last handler alone, as it sees an error raised after the parsers. */
	const last = (error: unknown, log = logger()) => {
		const { res, state } = fakeResponse();
		unexpectedErrors(log as never, "federation_grants")(error, {} as Request, res, vi.fn());
		return { state, log };
	};

	// Shaped as body-parser's `http-errors` are: `expose` and a 4xx `status`
	// on everything that is the caller's mistake.
	const exposed = (status: number, fields: Record<string, unknown>) => ({
		status,
		statusCode: status,
		expose: true,
		...fields,
	});

	it("answers 413 for a body over the limit, or more parameters than the parser takes", () => {
		for (const type of ["entity.too.large", "parameters.too.many"]) {
			const { state } = run(exposed(413, { type }));
			expect(state.status, type).toBe(413);
			expect(state.body).toEqual({ error: "invalid_request", error_description: "body_too_large" });
		}
	});

	it("answers 415 for a charset or a Content-Encoding the parser cannot decode", () => {
		for (const type of ["charset.unsupported", "encoding.unsupported"]) {
			const { state } = run(exposed(415, { type }));
			expect(state.status, type).toBe(415);
			expect(state.body).toEqual({
				error: "invalid_request",
				error_description: "unsupported_encoding",
			});
		}
	});

	it("answers 400 for a body it could not read, quoting none of it", () => {
		// `body-parser` puts the offending input into its message; a corrupt
		// compressed body is zlib's error, exposed as a 400 with no `type`.
		for (const error of [
			exposed(400, {
				type: "entity.parse.failed",
				message: "Unexpected token S in JSON at position 12 SENTINEL",
			}),
			exposed(400, { code: "Z_DATA_ERROR", message: "incorrect header check SENTINEL" }),
		]) {
			const { state } = run(error);
			expect(state.status).toBe(400);
			expect(state.body).toEqual({
				error: "invalid_request",
				error_description: "malformed_body",
			});
		}
	});

	it("answers 500 for an error that is not exposed, whatever its type claims", () => {
		const { state } = run({ type: "entity.too.large" });
		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
	});

	it("answers 500 for an exposed 4xx that is not a parser's — a store's 403 has failed", () => {
		// Raised after the parsers, it reaches the last handler only. An
		// `http-errors` 403 from a store is a failure, and it is logged.
		const { state, log } = last(
			Object.assign(new Error("forbidden"), { expose: true, status: 403 }),
		);
		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(log.error).toHaveBeenCalledWith(
			{
				site: "federation_grants",
				correlationId: "",
				err: expect.objectContaining({ name: "Error", detail: "forbidden", status: 403 }),
			},
			"federation_grants_unexpected_error",
		);
	});

	it("logs an unexpected error as its projection — never what a library put beside its message", () => {
		const { log } = last(
			Object.assign(new TypeError("cannot read a property"), { body: "SENTINEL" }),
		);
		expect(log.error).toHaveBeenCalledWith(
			{
				site: "federation_grants",
				correlationId: "",
				err: expect.objectContaining({ name: "TypeError", detail: "cannot read a property" }),
			},
			"federation_grants_unexpected_error",
		);
		expect(JSON.stringify(log.error.mock.calls)).not.toContain("SENTINEL");
	});

	/** `error` with a getter on `key` that throws when read. */
	const throwingOn = <E extends object>(error: E, key: string): E =>
		Object.defineProperty(error, key, {
			get() {
				throw new Error("getter");
			},
		});

	it.each([
		["a `name` getter that throws", () => throwingOn(new Error("m"), "name")],
		["a `status` getter that throws", () => throwingOn(new Error("m"), "status")],
		["a URIError whose `status` getter throws", () => throwingOn(new URIError("m"), "status")],
		[
			"a Proxy whose prototype cannot be read",
			() =>
				new Proxy(
					{},
					{
						getPrototypeOf() {
							throw new Error("trap");
						},
					},
				),
		],
	])("answers and logs an error with %s — the handlers never throw", (_label, make) => {
		// A throw inside the last handler reaches Express's own, which answers
		// HTML and logs nothing of ours.
		for (const handled of [run(make()), last(make())]) {
			expect(handled.state.status).toBe(500);
			expect(handled.state.body).toEqual({
				error: "server_error",
				error_description: "unexpected_error",
			});
			expect(handled.log.error).toHaveBeenCalledTimes(1);
			expect(handled.log.error.mock.calls[0]?.[1]).toBe("federation_grants_unexpected_error");
		}
	});

	it("answers a path Express could not decode as 400 malformed_path, wherever it surfaces", () => {
		const undecodable = Object.assign(new URIError("Failed to decode param '%zz'"), {
			status: 400,
		});
		for (const { state, log } of [run(undecodable), last(undecodable)]) {
			expect(state.status).toBe(400);
			expect(state.body).toEqual({ error: "invalid_request", error_description: "malformed_path" });
			expect(log.error).not.toHaveBeenCalled();
		}
	});

	it("answers 500 with a fixed description for anything else", () => {
		const { state } = run(new Error("something SENTINEL happened"));
		expect(state.status).toBe(500);
		expect(state.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
	});

	it("hands an error along once the answer has already gone out", () => {
		const { next } = run(new Error("late"), true);
		expect(next).toHaveBeenCalledTimes(1);
	});
});

describe("the hook that audits what middleware refused", () => {
	/** A response whose `finish` can be fired by hand. */
	const watchable = () => {
		let finish: () => void = () => undefined;
		const state = { status: 0, body: undefined as unknown };
		const res = {
			statusCode: 0,
			headers: { "x-request-id": "req-1" } as Record<string, string>,
			getHeader: (name: string) => res.headers[name],
			json(value: unknown) {
				state.body = value;
				return res;
			},
			on(event: string, listener: () => void) {
				if (event === "finish") finish = listener;
				return res;
			},
		};
		return { res: res as unknown as Response, state, finish: () => finish() };
	};

	const drive = async (
		statusCode: number,
		body: unknown,
		record: (event: unknown) => Promise<void> = async () => undefined,
	) => {
		const events: unknown[] = [];
		const background = createFederationGrantBackground();
		const { res, finish } = watchable();
		createRouteDenialAudit({
			sink: {
				kind: "test",
				record: async (event: unknown) => {
					events.push(event);
					await record(event);
				},
			} as never,
			operation: "token",
			now: () => new Date(),
			background,
		})(fakeRequest(), res, () => undefined);
		(res as unknown as { statusCode: number }).statusCode = statusCode;
		res.json(body);
		finish();
		await background.drain();
		return events as { details: { outcome: string } }[];
	};

	it("reads a code it does not know as what the status says", async () => {
		// `unexpectedErrors` answers `server_error` for a composition fault, and
		// `error` values this route never writes are the same question: a 5xx
		// is this provider's problem and a 4xx is the caller's.
		expect((await drive(500, { error: "server_error" }))[0]?.details.outcome).toBe("server_error");
		expect((await drive(400, { error: "something_new" }))[0]?.details.outcome).toBe(
			"invalid_request",
		);
		expect((await drive(418, undefined))[0]?.details.outcome).toBe("invalid_request");
	});

	it("does not let a sink that rejects take the process with it", async () => {
		// Nothing is waiting for this: the answer went out before the hook ran,
		// and an unhandled rejection from a detached audit would end a process
		// that was serving perfectly well.
		await expect(
			drive(401, { error: "invalid_client" }, async () => {
				throw new Error("sink is down");
			}),
		).resolves.toHaveLength(1);
	});
});
