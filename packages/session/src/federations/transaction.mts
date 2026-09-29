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
 * The federation transaction: a `form_post` federation's ephemeral state, held
 * outside the application session (README, "The transaction cookie").
 *
 * A `form_post` callback arrives as a **cross-site POST**, on which a
 * `SameSite=Lax` cookie is not sent. The flow needs *a* cookie that survives
 * one, and it must not be the session cookie: the start route is
 * unauthenticated, so anything it changed about the session cookie any third
 * party could change. So the cross-site part has its own cookie (an opaque id,
 * `HttpOnly; Secure; SameSite=None`, path-scoped to the callback route,
 * expiring with the transaction) and its own record (the envelope the callback
 * needs, deleted the moment the callback consumes it). The application session
 * cookie is never touched.
 *
 * **The record lives in the session store** under a key prefix of its own,
 * rather than in a component slot invented for it: that store is already
 * wired, covered by the replica-safety guard and pointed at Redis. The prefix
 * keeps the key spaces disjoint, so a transaction record can never be loaded
 * as a session, even by something that could forge a session cookie signature.
 */

import { randomBytes } from "node:crypto";

/**
 * How long a federation transaction may sit unconsumed: long enough to type a
 * password and satisfy the IdP's own MFA, short enough that an abandoned flow
 * leaves nothing meaningful behind. It bounds the transaction cookie's
 * `Max-Age` and the stored record's expiry together, so neither can outlive
 * the other.
 */
export const DEFAULT_FEDERATION_TRANSACTION_TTL_MS = 600_000; // 10 min

/**
 * Key prefix separating transaction records from the sessions sharing the
 * store. express-session generates its ids with `uid-safe`, which emits only
 * base64url characters, so no session id can collide with a key carrying it.
 */
export const FEDERATION_TRANSACTION_KEY_PREFIX = "fedtx:";

/** Appended to the deployment's session cookie name — cf. `<session.name>.csrf`. */
export const FEDERATION_TRANSACTION_COOKIE_SUFFIX = ".federation";

/** The ephemeral state a federation callback needs to complete the flow. */
export interface FederationTransactionEnvelope {
	readonly name: string;
	readonly state: string;
	readonly codeVerifier: string;
	/** OIDC nonce — absent for OAuth-only providers. */
	readonly nonce?: string | undefined;
	readonly redirectTo?: string | undefined;
	/**
	 * The start leg asked to link this identity to the account of the session
	 * `sid` (the one the browser held then) rather than to log in. A
	 * `form_post` callback arrives without the application session cookie, so
	 * the record is what says whose link this is.
	 */
	readonly link?: LinkIntent | undefined;
}

/**
 * What a `?link=1` start records: the session admission let link, and that
 * session's subject — together the callback's link claim (see ADR
 * 2026-09-28-session-admission). The callback refuses an intent without
 * `subject`.
 */
export interface LinkIntent {
	readonly sid: string;
	readonly subject?: string | undefined;
}

/**
 * The slice of an express-session `Store` this module uses.
 *
 * Structural rather than `import type { Store }` so a composition root may
 * hand over any store-shaped object, and so the harnesses in `__tests__` can
 * supply one without subclassing an abstract class.
 */
export interface FederationTransactionSessionStore {
	get(sid: string, callback: (err: unknown, record?: unknown) => void): void;
	set(sid: string, record: unknown, callback?: (err?: unknown) => void): void;
	destroy(sid: string, callback?: (err?: unknown) => void): void;
}

export interface FederationTransactionStore {
	/** Persist an envelope under `id`, expiring `ttlMs` from now. */
	set(id: string, envelope: FederationTransactionEnvelope, ttlMs: number): Promise<void>;
	/** Read an envelope back, or `null` when there is none to read. */
	get(id: string): Promise<FederationTransactionEnvelope | null>;
	/**
	 * Remove the record. Rejects when the store refuses, so the caller can
	 * decide whether an un-deletable — and therefore replayable — transaction
	 * is fatal. It is, on the path that consumes one.
	 */
	delete(id: string): Promise<void>;
}

/**
 * Mint an opaque, single-use transaction id.
 *
 * 256 bits from the CSPRNG. The id is a bearer value — presenting it is what
 * proves the callback reached the browser that started the flow — so it is
 * sized like one, not like the 128-bit `state` it accompanies.
 */
export const mintFederationTransactionId = (): string => randomBytes(32).toString("base64url");

/**
 * Name the transaction cookie after the deployment's session cookie, the way
 * the CSRF cookie is named: any prefix the session name carries is stripped
 * and `__Secure-` applied **unconditionally**, giving
 * `__Secure-<base>.federation` even for an unprefixed session cookie.
 *
 * `__Secure-` rather than `__Host-`, because `__Host-` requires `Path=/` and
 * this cookie is path-scoped to the callback route: every browser would
 * silently drop a `__Host-` name. Unconditionally, because this cookie is
 * `SameSite=None` and therefore *always* issued with `Secure`; the prefix
 * states that where a browser enforces it, so nothing, including an attacker
 * in a position to inject a cookie, can set it over a plain-HTTP hop.
 */
export const deriveFederationTransactionCookieName = (sessionCookieName: string): string => {
	const base = sessionCookieName.replace(/^__(?:Host|Secure)-/, "");
	return `__Secure-${base}${FEDERATION_TRANSACTION_COOKIE_SUFFIX}`;
};

const isLinkIntent = (
	value: unknown,
): value is { readonly sid: string; readonly subject?: unknown } =>
	typeof value === "object" &&
	value !== null &&
	typeof (value as { sid?: unknown }).sid === "string";

/** The intent as the callback reads it: the `sid`, and the subject when one was recorded. */
const readLinkIntent = (link: { readonly sid: string; readonly subject?: unknown }): LinkIntent =>
	typeof link.subject === "string" && link.subject.length > 0
		? { sid: link.sid, subject: link.subject }
		: { sid: link.sid };

/** Reject anything that is not the envelope this module wrote. */
const readEnvelope = (record: unknown): FederationTransactionEnvelope | null => {
	if (record == null || typeof record !== "object") return null;
	const envelope = (record as { federation?: unknown }).federation;
	if (envelope == null || typeof envelope !== "object") return null;
	const { name, state, codeVerifier, nonce, redirectTo, link } = envelope as Record<
		string,
		unknown
	>;
	if (typeof name !== "string" || typeof state !== "string" || typeof codeVerifier !== "string") {
		return null;
	}
	return {
		name,
		state,
		codeVerifier,
		...(typeof nonce === "string" ? { nonce } : {}),
		...(typeof redirectTo === "string" ? { redirectTo } : {}),
		...(isLinkIntent(link) ? { link: readLinkIntent(link) } : {}),
	};
};

/**
 * Adapt the express-session store the deployment already runs into a
 * transaction store.
 *
 * The record is shaped like a session (an envelope beside a `cookie` bearing
 * `expires`) because that is what the stores read to decide when a record
 * dies: `MemoryStore` drops it on the next read after `cookie.expires`, and
 * `connect-redis` turns the field into the key's `EX`. So an abandoned
 * transaction is reaped by the store itself, with no sweeper of ours.
 */
export const createFederationTransactionStore = (
	store: FederationTransactionSessionStore,
): FederationTransactionStore => {
	const key = (id: string): string => `${FEDERATION_TRANSACTION_KEY_PREFIX}${id}`;

	return {
		async set(id, envelope, ttlMs) {
			const expires = new Date(Date.now() + ttlMs);
			await new Promise<void>((resolve, reject) => {
				store.set(
					key(id),
					{
						cookie: { originalMaxAge: ttlMs, maxAge: ttlMs, expires, httpOnly: true, path: "/" },
						federation: envelope,
					},
					(err?: unknown) => (err ? reject(err as Error) : resolve()),
				);
			});
		},

		async get(id) {
			const record = await new Promise<unknown>((resolve, reject) => {
				store.get(key(id), (err: unknown, value?: unknown) =>
					err ? reject(err as Error) : resolve(value),
				);
			});
			return readEnvelope(record);
		},

		async delete(id) {
			await new Promise<void>((resolve, reject) => {
				store.destroy(key(id), (err?: unknown) => (err ? reject(err as Error) : resolve()));
			});
		},
	};
};
