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
 * The request and response the slot contract suites drive a component over,
 * without a server: the part of Express's a component of these slots is
 * held to. A request carries its headers (`headers`, `get`, `header`), its
 * own origin (`protocol`, `host`, `hostname`), a path, a parsed body,
 * and an express session — `session` with `regenerate` and `save` as
 * express-session has them, and `sessionID` — whose regenerations and saves
 * are counted. A response records `status`, `json` / `send` / `end`, the
 * headers `set` / `setHeader` / `header` / `append` / `vary` / `type`
 * wrote, `sendStatus`, each `cookie` it was given and each `clearCookie`. A
 * component that needs more of Express than this is outside the contracts.
 * Not on the testing entry.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";

/** The origin every fake request is served on. */
export const CONTRACT_ORIGIN = "https://idp.contract.test";
const CONTRACT_HOST = "idp.contract.test";

/** What happened to a fake request's express session. */
export interface FakeSessionRecord {
	/** Successful regenerations. */
	regenerated: number;
	/** Successful saves. */
	saved: number;
	/** The session's own fields as it was last saved; `undefined` before the first save. */
	lastSaved: Readonly<Record<string, unknown>> | undefined;
}

export interface FakeRequestOptions {
	readonly method?: string;
	readonly path?: string;
	/** Header names are matched without regard to case, as Node's are. */
	readonly headers?: Readonly<Record<string, string>>;
	/** The parsed body, as a body parser leaves it; empty by default. */
	readonly body?: Readonly<Record<string, unknown>>;
	/** Every `regenerate` fails with this: an express-session store that is down. */
	readonly regenerateFails?: unknown;
	/** Every `save` fails with this. */
	readonly saveFails?: unknown;
}

/** The express session a fake request carries: its fields are own, its operations are not. */
type FakeSession = Record<string, unknown> & {
	regenerate(done: (err?: unknown) => void): void;
	save(done: (err?: unknown) => void): void;
	destroy(done: (err?: unknown) => void): void;
};

/** A request with an anonymous express session, as express-session hands every request one. */
export function fakeRequest(options: FakeRequestOptions = {}): {
	readonly req: Request;
	readonly session: FakeSessionRecord;
} {
	const record: FakeSessionRecord = { regenerated: 0, saved: 0, lastSaved: undefined };
	const headers: Record<string, string> = { host: CONTRACT_HOST };
	for (const [name, value] of Object.entries(options.headers ?? {})) {
		headers[name.toLowerCase()] = value;
	}
	const path = options.path ?? "/contract";
	let generation = 0;
	const req = {
		method: options.method ?? "POST",
		path,
		url: path,
		originalUrl: path,
		protocol: "https",
		secure: true,
		host: CONTRACT_HOST,
		hostname: CONTRACT_HOST,
		ip: "192.0.2.10",
		headers,
		body: { ...(options.body ?? {}) },
		query: {},
		get(name: string): string | undefined {
			return headers[name.toLowerCase()];
		},
		header(name: string): string | undefined {
			return headers[name.toLowerCase()];
		},
		sessionID: "contract-session-0",
		session: undefined as FakeSession | undefined,
	};
	const newSession = (): FakeSession => {
		const session = {} as FakeSession;
		Object.defineProperties(session, {
			regenerate: {
				value: (done: (err?: unknown) => void) => {
					if (options.regenerateFails !== undefined) {
						done(options.regenerateFails);
						return;
					}
					generation++;
					record.regenerated++;
					req.sessionID = `contract-session-${generation}`;
					req.session = newSession();
					done();
				},
			},
			save: {
				value: (done: (err?: unknown) => void) => {
					if (options.saveFails !== undefined) {
						done(options.saveFails);
						return;
					}
					record.saved++;
					record.lastSaved = Object.freeze({ ...session });
					done();
				},
			},
			destroy: {
				value: (done: (err?: unknown) => void) => {
					req.session = undefined;
					done();
				},
			},
		});
		return session;
	};
	req.session = newSession();
	return { req: req as unknown as Request, session: record };
}

/** What a fake response was told. */
export interface FakeResponseRecord {
	status: number | undefined;
	body: unknown;
	ended: boolean;
	readonly headers: Record<string, string>;
	readonly cookies: Array<{
		readonly name: string;
		readonly value: string;
		readonly options: Readonly<Record<string, unknown>> | undefined;
	}>;
	/** The names `clearCookie` was called with, in order. */
	readonly cleared: string[];
}

export function fakeResponse(): { readonly res: Response; readonly record: FakeResponseRecord } {
	const record: FakeResponseRecord = {
		status: undefined,
		body: undefined,
		ended: false,
		headers: {},
		cookies: [],
		cleared: [],
	};
	/** Adds `value` to a header that may already carry some, comma-separated as Express appends. */
	const appendHeader = (name: string, value: unknown): void => {
		const key = name.toLowerCase();
		const current = record.headers[key];
		record.headers[key] = current === undefined ? String(value) : `${current}, ${String(value)}`;
	};
	const res = {
		statusCode: 200,
		headersSent: false,
		locals: {},
		status(code: number) {
			record.status = code;
			res.statusCode = code;
			return res;
		},
		json(body: unknown) {
			record.body = body;
			record.ended = true;
			res.headersSent = true;
			return res;
		},
		send(body?: unknown) {
			record.body = body;
			record.ended = true;
			res.headersSent = true;
			return res;
		},
		end() {
			record.ended = true;
			res.headersSent = true;
			return res;
		},
		set(name: string, value: unknown) {
			record.headers[name.toLowerCase()] = String(value);
			return res;
		},
		header(name: string, value: unknown) {
			return res.set(name, value);
		},
		setHeader(name: string, value: unknown) {
			record.headers[name.toLowerCase()] = String(value);
			return res;
		},
		get(name: string): string | undefined {
			return record.headers[name.toLowerCase()];
		},
		getHeader(name: string): string | undefined {
			return record.headers[name.toLowerCase()];
		},
		cookie(name: string, value: string, options?: Record<string, unknown>) {
			record.cookies.push({
				name,
				value,
				options: options === undefined ? undefined : Object.freeze({ ...options }),
			});
			return res;
		},
		clearCookie(name: string, _options?: Record<string, unknown>) {
			record.cleared.push(name);
			return res;
		},
		append(name: string, value: unknown) {
			appendHeader(name, value);
			return res;
		},
		vary(field: string) {
			appendHeader("vary", field);
			return res;
		},
		type(value: string) {
			record.headers["content-type"] = value;
			return res;
		},
		sendStatus(code: number) {
			res.status(code);
			return res.send(String(code));
		},
	};
	return { res: res as unknown as Response, record };
}

/** Runs `middleware` over a request: whether it handed the request on, and what it answered. */
export async function runMiddleware(
	middleware: RequestHandler,
	req: Request,
): Promise<{
	readonly next: number;
	readonly nextError: unknown;
	readonly response: FakeResponseRecord;
}> {
	const { res, record } = fakeResponse();
	let next = 0;
	let nextError: unknown;
	await new Promise<void>((resolve, reject) => {
		const onNext: NextFunction = (err?: unknown) => {
			next++;
			nextError = err;
			resolve();
		};
		try {
			const returned = middleware(req, res, onNext) as unknown;
			// A middleware that answers ends the response; one that hands on calls
			// `next`. Settled once a promise it returned settles and one turn of
			// the event loop has passed — a middleware that did neither by then
			// is reported as it is, with no answer and no `next`.
			Promise.resolve(returned).then(() => setImmediate(resolve), reject);
		} catch (err) {
			reject(err);
		}
	});
	return { next, nextError, response: record };
}
