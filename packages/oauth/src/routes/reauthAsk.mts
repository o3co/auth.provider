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
 * browser to the login page for `max_age` or `prompt=login` (or to a step-up
 * page), and consumes when the browser comes back.
 *
 * Not a request parameter: the caller could forge it and skip the round trip
 * OIDC Core §3.1.2.1 puts on the OP. Not a session field: the login it asks
 * for regenerates the session (against fixation), which would wipe it and
 * make `prompt=login` ask forever.
 *
 * An opaque 32-byte CSPRNG id on the URL names a record in the session store
 * under its own prefix: a caller cannot invent one that exists, it survives
 * session regeneration, `consume` is one store operation so a replay finds
 * nothing, and it is honoured only on a return to the request it was minted
 * for. The store is taken off the request (the one the session middleware
 * mounted) rather than injected, so it cannot point elsewhere. A login page
 * that rebuilds the authorize URL instead of returning `redirect_to` verbatim
 * drops the id, and the user is asked again.
 */

import { randomBytes } from "node:crypto";

/** How long a browser has to come back from the login page before the ask expires. */
export const REAUTH_ASK_TTL_MS = 10 * 60 * 1000;

/**
 * Key prefix separating ask records from sessions in the same store.
 * express-session ids (`uid-safe`) are base64url only, so none can collide.
 */
export const REAUTH_ASK_KEY_PREFIX = "reauth:";

/** The query parameter naming the ask on the URL the login page returns to. */
export const REAUTH_ASK_PARAM = "reauth_ask";

/**
 * One ask per authorization request, accumulating the login trip and a
 * step-up trip per requirement. Instants are epoch milliseconds: an
 * authentication must come strictly after the ask, and in whole seconds one
 * earlier in the same second would compare equal.
 */
export interface ReauthAskRecord {
	/**
	 * The canonical authorize request the ask was minted for, without the ask
	 * parameter itself. A return to a different request finds nothing.
	 */
	readonly request: string;
	/**
	 * When the first ask of this request was written, kept across its later
	 * trips: the cap on a chain of trips is measured from it. A record's own
	 * window is measured from its last write.
	 */
	readonly createdAt: number;
	/**
	 * When the browser was sent to the login page — the freshness reference
	 * for `max_age` and `prompt=login` — or `undefined` when it was not (a
	 * step-up trip alone). Carried from one record to the next, so a login
	 * asked before a step-up still stands after it.
	 */
	readonly loginAskedAt: number | undefined;
	/**
	 * When the browser was sent to each requirement's step-up page, by name: a
	 * session that comes back no later than its entry was already sent and is
	 * refused rather than sent again, while another requirement's trip is not.
	 */
	readonly stepUpAskedAt: Readonly<Record<string, number>>;
}

/**
 * The slice of an express-session `Store` this module uses: structural, so any
 * store-shaped object (or a test double) can be handed over.
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

const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

/**
 * When `record` was last written: each write stamps its stage (`loginAskedAt`
 * or a `stepUpAskedAt` entry), so the latest of them, else `createdAt`. Each
 * write opens its own `REAUTH_ASK_TTL_MS` window.
 */
const lastWrittenAt = (record: ReauthAskRecord): number =>
	Math.max(
		record.createdAt,
		record.loginAskedAt ?? Number.NEGATIVE_INFINITY,
		...Object.values(record.stepUpAskedAt),
	);

/**
 * Reject anything that is not the record this module wrote. A record in the
 * previous shape — `askedAt` and `request`, written before the ask
 * accumulated trips — reads as a login asked at `askedAt`, so a trip in
 * flight survives a rolling upgrade.
 */
const readRecord = (value: unknown): ReauthAskRecord | null => {
	if (value == null || typeof value !== "object") return null;
	const record = (value as { reauth?: unknown }).reauth;
	if (record == null || typeof record !== "object") return null;
	const { askedAt, request, createdAt, loginAskedAt, stepUpAskedAt } = record as Record<
		string,
		unknown
	>;
	if (typeof request !== "string") return null;
	if (isInstant(askedAt) && createdAt === undefined) {
		return { request, createdAt: askedAt, loginAskedAt: askedAt, stepUpAskedAt: {} };
	}
	if (!isInstant(createdAt)) return null;
	if (loginAskedAt !== undefined && !isInstant(loginAskedAt)) return null;
	if (stepUpAskedAt == null || typeof stepUpAskedAt !== "object" || Array.isArray(stepUpAskedAt)) {
		return null;
	}
	// A copy without a prototype: the keys are requirement names a store
	// round-tripped, looked up by name.
	const trips: Record<string, number> = Object.create(null);
	for (const [name, at] of Object.entries(stepUpAskedAt as Record<string, unknown>)) {
		if (!isInstant(at)) return null;
		trips[name] = at;
	}
	return { request, createdAt, loginAskedAt, stepUpAskedAt: trips };
};

/**
 * Adapt the deployment's express-session store into an ask store. The record
 * is shaped like a session (an envelope beside a `cookie` with `expires`)
 * because that is what stores read to expire a record — `MemoryStore` on read,
 * `connect-redis` as the key's `EX` — so an abandoned ask is reaped by the
 * store itself.
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
						reauth: {
							request: record.request,
							createdAt: record.createdAt,
							loginAskedAt: record.loginAskedAt,
							stepUpAskedAt: { ...record.stepUpAskedAt },
							// Rolling-upgrade compatibility: older replicas read only
							// `askedAt` and `request`, so a login ask stays readable to
							// them. Remove once no replica predates session admission.
							...(record.loginAskedAt === undefined ? {} : { askedAt: record.loginAskedAt }),
						},
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
			if (lastWrittenAt(record) + REAUTH_ASK_TTL_MS <= Date.now()) return null;
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
