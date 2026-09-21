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
 * How acquisition's three records are written down and read back (#593, D16,
 * slice 6).
 *
 * **Canonical, field by field.** The text a record encodes to is a function of
 * the record alone: the same intent encodes to the same bytes on every
 * instance and every release, which is what lets the admission script answer
 * `unchanged` for a retried write by comparing the stored text with the
 * incoming one. A spread, or `JSON.stringify` over an object whose key order
 * came from the caller, would make one retry look like a collision.
 *
 * **Nothing here heals a record it cannot read.** A text that does not decode
 * is refused, and the adapter turns that into a thrown error rather than a
 * `null`: reading it as absent would disable a live flow's checks, and
 * deleting it would make a rollback destroy flows a newer release wrote. That
 * is the grant store's treatment of unreadable state, deliberately unlike the
 * pending-consent adapter, which reclaims a corrupt record as it reads it.
 *
 * The values are not secret in the sense the grant credential is — a PKCE
 * verifier and a nonce are worthless once the flow ends, ten minutes at the
 * outside — so they are stored as the login flow's own transaction is: in the
 * clear, in a record with a deadline. What is sealed and why is D16's, and
 * this is the one record it does not seal.
 */

import type {
	FederationGrantBrowserBinding,
	FederationGrantConnectTransaction,
	FederationGrantConsentRecord,
	FederationGrantIntent,
} from "@o3co/auth-provider-core";

const BAD = (what: string): Error =>
	new Error(
		`federation grant intent store: ${what} — refused rather than read as absent, because a record ` +
			"this release cannot parse may be a newer one's, and a flow in progress must not be quietly voided",
	);

const str = (value: unknown, what: string): string => {
	if (typeof value !== "string" || value.length === 0) throw BAD(what);
	return value;
};

const optionalStr = (value: unknown, what: string): string | undefined => {
	if (value === undefined || value === null) return undefined;
	if (typeof value !== "string" || value.length === 0) throw BAD(what);
	return value;
};

const num = (value: unknown, what: string): number => {
	if (typeof value !== "number" || !Number.isFinite(value)) throw BAD(what);
	return value;
};

const date = (value: unknown, what: string): Date => {
	const ms = num(value, what);
	const at = new Date(ms);
	if (Number.isNaN(at.getTime())) throw BAD(what);
	return at;
};

const strings = (value: unknown, what: string): readonly string[] => {
	if (!Array.isArray(value)) throw BAD(what);
	return value.map((entry, index) => str(entry, `${what}[${index}]`));
};

const params = (value: unknown, what: string): Readonly<Record<string, string>> => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw BAD(what);
	const out: Record<string, string> = {};
	// Sorted, so that two records differing only in the order an operator wrote
	// their parameters encode to the same text.
	for (const key of Object.keys(value as Record<string, unknown>).sort()) {
		// A string, and possibly an empty one: the connection resolver accepts
		// `login_hint: ""`, and a codec stricter than the configuration it stores
		// turns a working connection into a storage failure (Codex).
		const param = (value as Record<string, unknown>)[key];
		if (typeof param !== "string") throw BAD(`${what}.${key}`);
		out[key] = param;
	}
	return out;
};

const parse = (text: string, what: string): Record<string, unknown> => {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		throw BAD(`${what} is not JSON`);
	}
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw BAD(what);
	return value as Record<string, unknown>;
};

const bindingText = (binding: FederationGrantBrowserBinding): string =>
	// Length-prefixed: two bindings that differ only in where a separator falls
	// must not compare equal, and the answering script compares this as one
	// string rather than parsing anything.
	`${binding.sessionId.length}:${binding.sessionId}:${binding.sid.length}:${binding.sid}:${binding.subject.length}:${binding.subject}`;

export { bindingText as federationGrantBindingText };

/** Length-prefixed, for the same reason: the bound is on the pair, not on a concatenation. */
export const federationGrantIntentPairText = (clientId: string, subject: string): string =>
	`${clientId.length}:${clientId}:${subject.length}:${subject}`;

export function encodeFederationGrantIntent(record: FederationGrantIntent): string {
	return JSON.stringify({
		handle: record.handle,
		kind: record.kind,
		grantId: record.grantId,
		clientId: record.clientId,
		subject: record.subject,
		connection: record.connection,
		federation: record.federation,
		identityRevision: record.identityRevision,
		authorizationRevision: record.authorizationRevision,
		callbackUri: record.callbackUri,
		scopes: [...record.scopes],
		resource: record.resource ?? null,
		authorizationParams: params(record.authorizationParams, "authorizationParams"),
		redirectUri: record.redirectUri,
		clientState: record.clientState,
		upstreamSubject: record.upstreamSubject ?? null,
		lifetimeMs: record.lifetimeMs,
		createdAt: record.createdAt.getTime(),
		expiresAt: record.expiresAt.getTime(),
		correlationId: record.correlationId,
	});
}

export function decodeFederationGrantIntent(text: string): FederationGrantIntent {
	const raw = parse(text, "an intent record");
	const resource = optionalStr(raw.resource, "intent resource");
	const upstreamSubject = optionalStr(raw.upstreamSubject, "intent upstream subject");
	const kind = raw.kind;
	if (kind !== "initial" && kind !== "reauthorization") throw BAD("an intent's kind");
	return {
		handle: str(raw.handle, "intent handle"),
		kind,
		grantId: str(raw.grantId, "intent grant id"),
		clientId: str(raw.clientId, "intent client id"),
		subject: str(raw.subject, "intent subject"),
		connection: str(raw.connection, "intent connection"),
		federation: str(raw.federation, "intent federation"),
		identityRevision: str(raw.identityRevision, "intent identity revision"),
		authorizationRevision: str(raw.authorizationRevision, "intent authorization revision"),
		callbackUri: str(raw.callbackUri, "intent callback uri"),
		scopes: strings(raw.scopes, "intent scopes"),
		...(resource !== undefined ? { resource } : {}),
		authorizationParams: params(raw.authorizationParams, "intent authorization params"),
		redirectUri: str(raw.redirectUri, "intent redirect uri"),
		clientState: str(raw.clientState, "intent client state"),
		...(upstreamSubject !== undefined ? { upstreamSubject } : {}),
		lifetimeMs: num(raw.lifetimeMs, "intent lifetime"),
		createdAt: date(raw.createdAt, "intent createdAt"),
		expiresAt: date(raw.expiresAt, "intent expiresAt"),
		correlationId: str(raw.correlationId, "intent correlation id"),
	};
}

const encodeBinding = (binding: FederationGrantBrowserBinding) => ({
	sessionId: binding.sessionId,
	sid: binding.sid,
	subject: binding.subject,
});

const decodeBinding = (raw: unknown, what: string): FederationGrantBrowserBinding => {
	if (typeof raw !== "object" || raw === null) throw BAD(what);
	const fields = raw as Record<string, unknown>;
	return {
		sessionId: str(fields.sessionId, `${what} session id`),
		sid: str(fields.sid, `${what} sid`),
		subject: str(fields.subject, `${what} subject`),
	};
};

export function encodeFederationGrantConsent(record: FederationGrantConsentRecord): string {
	return JSON.stringify({
		challenge: record.challenge,
		intentHandle: record.intentHandle,
		binding: encodeBinding(record.binding),
		scopes: [...record.scopes],
		lifetimeMs: record.lifetimeMs,
		createdAt: record.createdAt.getTime(),
		expiresAt: record.expiresAt.getTime(),
	});
}

export function decodeFederationGrantConsent(text: string): FederationGrantConsentRecord {
	const raw = parse(text, "a consent record");
	return {
		challenge: str(raw.challenge, "consent challenge"),
		intentHandle: str(raw.intentHandle, "consent intent handle"),
		binding: decodeBinding(raw.binding, "consent binding"),
		scopes: strings(raw.scopes, "consent scopes"),
		lifetimeMs: num(raw.lifetimeMs, "consent lifetime"),
		createdAt: date(raw.createdAt, "consent createdAt"),
		expiresAt: date(raw.expiresAt, "consent expiresAt"),
	};
}

export function encodeFederationGrantTransaction(
	record: FederationGrantConnectTransaction,
): string {
	return JSON.stringify({
		state: record.state,
		intent: JSON.parse(encodeFederationGrantIntent(record.intent)),
		binding: encodeBinding(record.binding),
		codeVerifier: record.codeVerifier,
		nonce: record.nonce,
		consent: {
			at: record.consent.at.getTime(),
			sid: record.consent.sid,
			scopes: [...record.consent.scopes],
		},
		grantExpiresAt: record.grantExpiresAt.getTime(),
		createdAt: record.createdAt.getTime(),
		expiresAt: record.expiresAt.getTime(),
	});
}

export function decodeFederationGrantTransaction(text: string): FederationGrantConnectTransaction {
	const raw = parse(text, "a connect transaction");
	const consent = raw.consent;
	if (typeof consent !== "object" || consent === null) throw BAD("a transaction's consent");
	const fields = consent as Record<string, unknown>;
	const intent = raw.intent;
	if (typeof intent !== "object" || intent === null) throw BAD("a transaction's intent");
	return {
		state: str(raw.state, "transaction state"),
		intent: decodeFederationGrantIntent(JSON.stringify(intent)),
		binding: decodeBinding(raw.binding, "transaction binding"),
		codeVerifier: str(raw.codeVerifier, "transaction code verifier"),
		nonce: str(raw.nonce, "transaction nonce"),
		consent: {
			at: date(fields.at, "transaction consent at"),
			sid: str(fields.sid, "transaction consent sid"),
			scopes: strings(fields.scopes, "transaction consent scopes"),
		},
		grantExpiresAt: date(raw.grantExpiresAt, "transaction grant expiry"),
		createdAt: date(raw.createdAt, "transaction createdAt"),
		expiresAt: date(raw.expiresAt, "transaction expiresAt"),
	};
}
