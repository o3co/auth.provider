import type { Grant, GrantOutcome } from "@mod/grants";
import { type Log, sameSecret, Unavailable } from "@mod/kernel";
import type { Sessions } from "@mod/session";
import { type AccessGrant, referenceOf, type Tokens } from "@mod/tokens";
import { type CodeRecord, fromStored, s256, toStored, verifierShape } from "./codes.ts";
import {
	type Addition,
	codeGrantType,
	type IdTokenMaker,
	type IdTokenRequest,
	type Redeemed,
	type SessionRedemption,
} from "./contract.ts";
import type { ChangedCode, CodeStore, VoidList } from "./store.ts";

/** One answer for every refused code, so it tells nothing about why. */
const refused: GrantOutcome = {
	kind: "error",
	error: "invalid_grant",
	description: "invalid code",
};
/** An answer that leaves the code unused. */
const malformed = (description: string): GrantOutcome => ({
	kind: "error",
	error: "invalid_request",
	description,
});
/** The answer's own fields, which no addition may take. */
export const answerFields = new Set([
	"access_token",
	"token_type",
	"expires_in",
	"scope",
	"id_token",
]);
/** The issued token's record outlives the token by this much, for clock drift between hosts. */
const allowanceMs = 120_000;

const changed = (record: CodeRecord): ChangedCode => ({ value: toStored(record) });
/** A record changed as given, living until a token's end and the allowance after it. */
const lasting = (record: CodeRecord, expiresAt: number, now: number): ChangedCode => ({
	value: toStored(record),
	lifetimeMs: Math.max(1, expiresAt - now + allowanceMs),
});

/** What the ID token maker is told about a redeemed code. */
const idTokenRequest = (record: CodeRecord, clientId: string): IdTokenRequest => ({
	subject: record.subject,
	clientId,
	...(record.nonce !== undefined ? { nonce: record.nonce } : {}),
	authenticatedAt: record.authenticatedAt,
	...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
	amr: record.amr,
	...(record.acr !== undefined ? { acr: record.acr } : {}),
	scope: record.scope,
	session: record.session,
});

const accessOf = (record: CodeRecord, clientId: string): AccessGrant => ({
	subject: record.subject,
	issuedTo: clientId,
	audience: record.audience,
	scope: record.scope,
	amr: record.amr,
	authenticatedAt: record.authenticatedAt,
	...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
	...(record.acr !== undefined ? { acr: record.acr } : {}),
});

export function voiding(parts: {
	readonly store: CodeStore;
	readonly voids: VoidList;
	readonly tokens: Tokens;
	readonly log: Log;
	readonly now: () => number;
	readonly additions: readonly Addition[];
}) {
	const { store, voids, tokens, log, now, additions } = parts;
	/** Marks a known record void, even if it is already; one that issued a token lives as long. */
	const mark = async (name: string) => {
		const at = now();
		const marked = await store.update(name, (kept) => {
			const r = fromStored(kept);
			if (!r) return undefined;
			const voided = { ...r, void: true };
			return r.token ? lasting(voided, r.token.expiresAt, at) : changed(voided);
		});
		return marked && fromStored(marked.after);
	};
	/** Ends what the additions gave for a code, then takes it off the void list. */
	const finish = async (name: string) => {
		for (const addition of additions) await addition.revoke?.(name);
		await voids.done(name);
	};
	/** Voids a code: listed first, it stays listed until its token is revoked or its record is gone. */
	const settle = async (name: string) => {
		await voids.add(name);
		const record = await mark(name);
		if (!record) {
			log.info("code-grant.void_without_record", {});
			await finish(name);
			return;
		}
		// Not issued yet: the request issuing it sees the mark and voids again.
		if (!record.token) return;
		const revoked = await tokens.revokeReferenced(record.token.reference);
		if (revoked.kind === "unsupported") throw new Unavailable("code-grant");
		await finish(name);
	};
	const sweep = async () => {
		const { failed } = await voids.each(settle);
		if (failed > 0) log.warn("code-grant.void_retry_failed", { count: failed });
	};
	return { settle, sweep };
}

export function codeGrant(parts: {
	readonly store: CodeStore;
	readonly sessions: Sessions;
	readonly settle: (name: string) => Promise<void>;
	readonly now: () => number;
	readonly idToken: IdTokenMaker | undefined;
	readonly additions: readonly Addition[];
	readonly redemptions: readonly SessionRedemption[];
}): Grant {
	const { store, sessions, settle, now, idToken, additions, redemptions } = parts;
	/** Whether the code's session enters at use: not closed, ended or short of a requirement. */
	const enters = async (session: string) => (await sessions.entryOf(session)).kind === "entered";
	return {
		grantType: codeGrantType,
		targets: true,
		handle: async ({ client, param, admits, issue, binding, target }) => {
			const code = param("code");
			const redirectUri = param("redirect_uri");
			const verifier = param("code_verifier");
			if (!code || !redirectUri || !verifier) {
				return malformed("code, redirect_uri and code_verifier are required");
			}
			if (!verifierShape.test(verifier)) return malformed("malformed code_verifier");
			const name = store.nameOf(code);
			const presented = (r: CodeRecord) =>
				r.clientId === client.id &&
				r.redirectUri === redirectUri &&
				sameSecret(s256(verifier), r.challenge);
			// Asked before use, by whoever may redeem it; with the code's one audience, the rule only refuses.
			const peeked = await store.update(name, () => undefined);
			const unused = peeked && fromStored(peeked.before);
			if (unused?.state === "issued" && presented(unused)) {
				const asked = target(unused.audience, (audience) => unused.audience.includes(audience));
				if (asked.kind === "error") return asked;
				const admitted = await admits(accessOf(unused, client.id), { session: unused.session });
				if (admitted.kind === "refused") return admitted;
			}
			// Used up before it is checked: of two racing uses, only the one that turned it consumed goes on.
			const used = await store.update(name, (kept) => {
				const r = fromStored(kept);
				return r?.state === "issued" ? changed({ ...r, state: "consumed" }) : undefined;
			});
			const record = used && fromStored(used.before);
			if (!record) return refused;
			if (record.state === "consumed") {
				await settle(name);
				return refused;
			}
			if (!presented(record)) return refused;
			if (!(await enters(record.session))) return refused;
			// Asked again on what was used up: a look before use that missed the code asked nothing.
			const again = target(record.audience, (audience) => record.audience.includes(audience));
			if (again.kind === "error") return again;
			const allowed = await issue(accessOf(record, client.id), { session: record.session });
			if (allowed.kind === "refused") return allowed;
			const issued = allowed.access;
			// Read once, outside the change: it may run again on a race.
			const at = now();
			const given = { reference: referenceOf(issued), expiresAt: issued.expiresAt };
			// A record gone meanwhile is never written back (the code would be unused again), nor its token answered.
			const noted = await store.update(name, (kept) => {
				const r = fromStored(kept);
				return r && lasting({ ...r, token: given }, issued.expiresAt, at);
			});
			const after = noted && fromStored(noted.after);
			if (!after) return refused;
			// From here a step that fails, even before it gives a promise, voids the code.
			const voidIfFails = async <T>(step: () => Promise<T>): Promise<T> => {
				try {
					return await step();
				} catch (error) {
					await settle(name);
					throw error;
				}
			};
			for (const redemption of redemptions) {
				await voidIfFails(() => redemption.redeemed(record.session, client.id));
			}
			// A reuse or a logout that came while the token was being made voids it.
			if (after.void || !(await enters(record.session))) {
				await settle(name);
				return refused;
			}
			const maker = idToken && record.scope.includes(idToken.scope) ? idToken : undefined;
			const id = maker && (await voidIfFails(() => maker.make(idTokenRequest(record, client.id))));
			const { token: _, ...access } = issued;
			const redeemed: Redeemed = {
				redemption: name,
				client,
				subject: record.subject,
				scope: record.scope,
				audience: record.audience,
				session: record.session,
				authenticatedAt: record.authenticatedAt,
				...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
				amr: record.amr,
				...(record.acr !== undefined ? { acr: record.acr } : {}),
				access,
				...(binding ? { binding } : {}),
			};
			const added: Record<string, string> = {};
			for (const addition of additions) {
				const value = await voidIfFails(() => addition.issue(redeemed));
				if (value !== undefined) added[addition.field] = value;
			}
			return {
				kind: "issued",
				body: {
					...added,
					...(id ? { id_token: id } : {}),
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					...(record.scope.length > 0 ? { scope: record.scope.join(" ") } : {}),
				},
			};
		},
	};
}
