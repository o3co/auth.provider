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
 * outside the application session (#494).
 *
 * A `form_post` callback arrives as a **cross-site POST** from the IdP's
 * origin, and a `SameSite=Lax` cookie — the deployment default, and the right
 * default — is not sent on one. The flow therefore needs *a* cookie that
 * survives a cross-site POST. It does not need *the session* cookie to be that
 * cookie, and making it one is what #494 was: the start route is unauthenticated,
 * so any third party who caused one navigation permanently downgraded the
 * victim's authenticated session cookie to `SameSite=None`.
 *
 * So the cross-site part is given its own cookie and its own record:
 *
 * - the cookie carries nothing but an opaque id, is `HttpOnly; Secure;
 *   SameSite=None`, is path-scoped to the one callback route that reads it, and
 *   expires with the transaction rather than with the session;
 * - the record holds the envelope the callback needs — `state`, `codeVerifier`,
 *   `nonce`, `redirectTo`, provider name — and is deleted the moment the
 *   callback consumes it.
 *
 * The application session cookie is never touched, and a browser that abandons
 * the flow at the IdP is left holding one short-lived cookie that expires on
 * its own.
 *
 * **The record lives in the session store**, keyed under a prefix of its own,
 * rather than in a component slot invented for it. That store is already wired,
 * already covered by the replica-safety guard (#474), and already the thing a
 * deployment points at Redis; a second slot would be a second thing to
 * configure and a second thing to get wrong. The prefix keeps the two key
 * spaces disjoint, so a transaction record can never be loaded as a session
 * even by something that could forge a session cookie signature.
 */

import { randomBytes } from "node:crypto";

/**
 * How long a federation transaction may sit unconsumed.
 *
 * The window a user has between being redirected to the IdP and coming back:
 * long enough to type a password and satisfy the IdP's own MFA, short enough
 * that an abandoned flow leaves nothing meaningful behind. It bounds the
 * transaction cookie's `Max-Age` and the stored record's expiry together, so
 * neither can outlive the other.
 */
export const DEFAULT_FEDERATION_TRANSACTION_TTL_MS = 600_000; // 10 min

/**
 * Key prefix separating transaction records from the sessions sharing the
 * store.
 *
 * express-session generates its ids with `uid-safe`, which emits only
 * base64url characters, so no session id can ever collide with a key that
 * carries this prefix.
 */
export const FEDERATION_TRANSACTION_KEY_PREFIX = "fedtx:";

/** Appended to the deployment's session cookie name — cf. `<session.name>.csrf`. */
export const FEDERATION_TRANSACTION_COOKIE_SUFFIX = ".federation";

/** The ephemeral state a federation callback needs to complete the flow. */
export interface FederationTransactionEnvelope {
	readonly name: string;
	readonly state: string;
	readonly codeVerifier: string;
	/** PB-4 nonce — absent for OAuth-only providers. */
	readonly nonce?: string | undefined;
	readonly redirectTo?: string | undefined;
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
 * the CSRF cookie is named.
 *
 * One deviation, and it matters: a `__Host-` name is swapped for `__Secure-`.
 * `__Host-` requires `Path=/`, and this cookie is deliberately path-scoped to
 * the callback route, so a `__Host-` name would be silently dropped by every
 * browser and the callback would fail with nothing visibly wrong. `__Secure-`
 * asserts what this cookie actually guarantees — it is only ever set with
 * `Secure` — and carries no path constraint.
 */
export const deriveFederationTransactionCookieName = (sessionCookieName: string): string => {
	const base = sessionCookieName.replace(/^__(?:Host|Secure)-/, "");
	return `__Secure-${base}${FEDERATION_TRANSACTION_COOKIE_SUFFIX}`;
};

/** Reject anything that is not the envelope this module wrote. */
const readEnvelope = (record: unknown): FederationTransactionEnvelope | null => {
	if (record == null || typeof record !== "object") return null;
	const envelope = (record as { federation?: unknown }).federation;
	if (envelope == null || typeof envelope !== "object") return null;
	const { name, state, codeVerifier, nonce, redirectTo } = envelope as Record<string, unknown>;
	if (typeof name !== "string" || typeof state !== "string" || typeof codeVerifier !== "string") {
		return null;
	}
	return {
		name,
		state,
		codeVerifier,
		...(typeof nonce === "string" ? { nonce } : {}),
		...(typeof redirectTo === "string" ? { redirectTo } : {}),
	};
};

/**
 * Adapt the express-session store the deployment already runs into a
 * transaction store.
 *
 * The record is shaped like a session — an envelope beside a `cookie` bearing
 * `expires` — because that shape is what the store implementations read to
 * decide when a record dies. `MemoryStore` drops a record whose
 * `cookie.expires` has passed on the next read; `connect-redis` turns the same
 * field into the Redis key's `EX`. Writing the expiry there means an abandoned
 * transaction is reaped by the store itself, with no sweeper of ours, in both
 * deployments.
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
