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
 * The re-authentication ask: the record `/authorize` writes when it sends a
 * browser to the login page for `max_age` or `prompt=login`, and consumes when
 * the browser comes back (#481).
 *
 * ## Why it is a record and not a parameter
 *
 * It was a parameter — `reauth_after=<epoch second>` on the authorize URL the
 * login page returns to — read straight back off the request. The value is the
 * caller's: `max_age=60&reauth_after=0` satisfied "authenticated at or after
 * the ask" for any live session and skipped the round trip the parameter
 * exists to force. OIDC Core §3.1.2.1 puts re-authentication on the OP, so a
 * forgeable marker turns a mandatory control into an RP's optional `auth_time`
 * check.
 *
 * ## Why it is not on the session either
 *
 * Because the login it asks for destroys the session: `/session/login`
 * regenerates (session fixation, correctly) and restores only
 * `isAuthenticated`, `user`, `redirectTo` and `sid`. A field on the session
 * would be wiped by the very authentication that satisfies it, and
 * `prompt=login` — whose staleness test is unconditional — would ask again
 * forever.
 *
 * ## What it is
 *
 * An opaque id on the URL, naming a record in the session store under a prefix
 * of its own. The id is 32 bytes from the CSPRNG, so a caller cannot invent one
 * that exists; the record survives session regeneration because it is not in
 * the session; and `consume` is one store operation, so a replay finds
 * nothing. The record carries the canonical authorize request it was minted
 * for, and is honoured only on a return to that same request — an outstanding
 * ask for one request cannot satisfy another request's freshness requirement.
 *
 * The store is taken off the request, as the federation transaction's is
 * (#494), rather than injected: that is where the store the session middleware
 * mounted actually is, and a second wiring of the same store is a second thing
 * that can point somewhere else.
 *
 * What this does **not** fix: a deployment login page that rebuilds the
 * authorize URL instead of returning `redirect_to` verbatim drops the id, so
 * the request is asked to authenticate again. That is the documented contract
 * of the login round trip and it was equally true of the parameter.
 */

import { randomBytes } from "node:crypto";

/** How long a browser has to come back from the login page before the ask expires. */
export const REAUTH_ASK_TTL_MS = 10 * 60 * 1000;

/**
 * Key prefix separating ask records from the sessions sharing the store.
 *
 * express-session generates its ids with `uid-safe`, which emits only
 * base64url characters, so no session id can collide with a key carrying this
 * prefix — the same reasoning as the federation transaction's prefix.
 */
export const REAUTH_ASK_KEY_PREFIX = "reauth:";

/** The query parameter naming the ask on the URL the login page returns to. */
export const REAUTH_ASK_PARAM = "reauth_ask";

export interface ReauthAskRecord {
	/**
	 * Epoch milliseconds at which this endpoint asked for a re-authentication.
	 * Milliseconds, not seconds: an authentication must come strictly after the
	 * ask, and in whole seconds a session created earlier in the same second
	 * compared equal (v0.13.0 audit).
	 */
	readonly askedAt: number;
	/**
	 * The canonical authorize request the ask was minted for, without the ask
	 * parameter itself. A return to a different request finds nothing.
	 */
	readonly request: string;
}

/**
 * The slice of an express-session `Store` this module uses.
 *
 * Structural rather than `import type { Store }`, so a composition root may
 * hand over any store-shaped object and a test harness can supply one without
 * subclassing an abstract class.
 */
export interface ReauthAskSessionStore {
	get(sid: string, callback: (err: unknown, record?: unknown) => void): void;
	set(sid: string, record: unknown, callback?: (err?: unknown) => void): void;
	destroy(sid: string, callback?: (err?: unknown) => void): void;
}

export interface ReauthAskStore {
	/** Mint an id, record the ask under it, and return the id. */
	ask(record: ReauthAskRecord): Promise<string>;
	/**
	 * The ask `id` names, if it is for `request` — removed in the same step, so
	 * a replay finds nothing. `null` when there is no such ask, when it was
	 * minted for another request, or when it has expired.
	 */
	consume(id: string, request: string): Promise<ReauthAskRecord | null>;
}

/** Reject anything that is not the record this module wrote. */
const readRecord = (value: unknown): ReauthAskRecord | null => {
	if (value == null || typeof value !== "object") return null;
	const record = (value as { reauth?: unknown }).reauth;
	if (record == null || typeof record !== "object") return null;
	const { askedAt, request } = record as Record<string, unknown>;
	if (typeof askedAt !== "number" || !Number.isFinite(askedAt)) return null;
	if (typeof request !== "string") return null;
	return { askedAt, request };
};

/**
 * Adapt the express-session store the deployment already runs into an ask
 * store.
 *
 * The record is shaped like a session — an envelope beside a `cookie` bearing
 * `expires` — because that shape is what the store implementations read to
 * decide when a record dies: `MemoryStore` drops one whose `cookie.expires`
 * has passed on the next read, and `connect-redis` turns the same field into
 * the key's `EX`. An abandoned ask is therefore reaped by the store itself,
 * with no sweeper of ours, in both deployments. The same envelope the
 * federation transaction uses (#494).
 */
export const createReauthAskStore = (store: ReauthAskSessionStore): ReauthAskStore => {
	const key = (id: string): string => `${REAUTH_ASK_KEY_PREFIX}${id}`;

	return {
		async ask(record) {
			// 256 bits from the CSPRNG: presenting the id is what proves the
			// browser was sent to the login page by this server, so it is sized
			// like the bearer value it is.
			const id = randomBytes(32).toString("base64url");
			const expires = new Date(Date.now() + REAUTH_ASK_TTL_MS);
			await new Promise<void>((resolve, reject) => {
				store.set(
					key(id),
					{
						cookie: {
							originalMaxAge: REAUTH_ASK_TTL_MS,
							maxAge: REAUTH_ASK_TTL_MS,
							expires,
							httpOnly: true,
							path: "/",
						},
						reauth: { askedAt: record.askedAt, request: record.request },
					},
					(err?: unknown) => (err ? reject(err as Error) : resolve()),
				);
			});
			return id;
		},

		async consume(id, request) {
			const value = await new Promise<unknown>((resolve, reject) => {
				store.get(key(id), (err: unknown, record?: unknown) =>
					err ? reject(err as Error) : resolve(record),
				);
			});
			const record = readRecord(value);
			if (record === null) return null;
			// Destroy whatever was found, matching or not: an ask presented once
			// is spent, so a mismatch cannot be retried against another request.
			await new Promise<void>((resolve, reject) => {
				store.destroy(key(id), (err?: unknown) => (err ? reject(err as Error) : resolve()));
			});
			if (record.request !== request) return null;
			if (record.askedAt + REAUTH_ASK_TTL_MS <= Date.now()) return null;
			return record;
		},
	};
};

/**
 * The ask store behind this request, or `undefined` when no session middleware
 * mounted one. A request that reaches `/authorize` without a session store has
 * no composition to record an ask in, which is a composition error rather than
 * a per-request condition — the endpoint refuses rather than proceeding.
 */
export const reauthAskStoreFor = (req: unknown): ReauthAskStore | undefined => {
	const store = (req as { sessionStore?: unknown }).sessionStore;
	if (store == null || typeof store !== "object") return undefined;
	const candidate = store as Partial<ReauthAskSessionStore>;
	if (
		typeof candidate.get !== "function" ||
		typeof candidate.set !== "function" ||
		typeof candidate.destroy !== "function"
	) {
		return undefined;
	}
	return createReauthAskStore(candidate as ReauthAskSessionStore);
};
