import type { Grant, GrantOutcome } from "@mod/grants";
import { sameSecret, Unavailable } from "@mod/kernel";
import type { Sessions } from "@mod/session";
import { type AccessGrant, referenceOf } from "@mod/tokens";
import { type CodeRecord, fromStored, s256, toStored, verifierShape } from "./codes.ts";
import {
	type Addition,
	codeGrantType,
	type IdTokenMaker,
	type IdTokenRequest,
	type Redeemed,
	type RedemptionHook,
	type SessionRedemption,
} from "./contract.ts";
import {
	createRedemptionRecord,
	isRedeemed,
	noteToken,
} from "./redemption-record/redemption-record.ts";
import type { ChangedCode, CodeStore, RedemptionRecords } from "./store.ts";

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
/** A code's record changed as given, keeping its end: a code is never kept longer than issued. */
const changed = (record: CodeRecord): ChangedCode => ({ value: toStored(record) });

/** What the ID token maker is told about a redeemed code. */
const idTokenRequest = (record: CodeRecord, clientId: string, name: string): IdTokenRequest => ({
	subject: record.subject,
	clientId,
	...(record.nonce !== undefined ? { nonce: record.nonce } : {}),
	authenticatedAt: record.authenticatedAt,
	...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
	amr: record.amr,
	...(record.acr !== undefined ? { acr: record.acr } : {}),
	scope: record.scope,
	session: record.session,
	redemption: name,
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

export function codeGrant(parts: {
	readonly store: CodeStore;
	readonly redemptionRecords: RedemptionRecords;
	readonly sessions: Sessions;
	readonly settle: (name: string) => Promise<void>;
	readonly now: () => number;
	readonly idToken: IdTokenMaker | undefined;
	readonly additions: readonly Addition[];
	readonly redemptions: readonly SessionRedemption[];
	readonly hooks: readonly RedemptionHook[];
}): Grant {
	const {
		store,
		redemptionRecords,
		sessions,
		settle,
		now,
		idToken,
		additions,
		redemptions,
		hooks,
	} = parts;
	/** Whether the code's session enters at use: not closed, ended or short of a requirement. */
	const enters = async (session: string) => (await sessions.entryOf(session)).kind === "entered";
	return {
		grantType: codeGrantType,
		readsAmbient: "none",
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
			const used = await store.update(name, (stored) => {
				const r = fromStored(stored);
				return r?.state === "issued" ? changed({ ...r, state: "consumed" }) : undefined;
			});
			const record = used && fromStored(used.before);
			if (!record) {
				// A code gone, its own record ended, may still have been redeemed: its token is revoked
				// from its redemption record, which outlives it.
				if (await isRedeemed(redemptionRecords, name)) await settle(name);
				return refused;
			}
			if (record.state === "consumed") {
				await settle(name);
				return refused;
			}
			if (!presented(record)) return refused;
			const entry = await sessions.entryOf(record.session);
			if (entry.kind !== "entered") return refused;
			// Asked again on what was used up: a look before use that missed the code asked nothing.
			const again = target(record.audience, (audience) => record.audience.includes(audience));
			if (again.kind === "error") return again;
			// Its record is made once used up and before issuing (use-up, create, issue, note), under
			// its subject's tombstone (`redemption-record`): a subject erased meanwhile gets no token.
			const { made, tokenEnd } = await createRedemptionRecord(
				redemptionRecords,
				name,
				record.subject,
				now,
			);
			if (made === "erased") {
				await settle(name);
				return refused;
			}
			// Only this request turned the code consumed: a record there already is no state it knows.
			if (made !== "created") throw new Unavailable("code-grant");
			// Pinned once used up and before issuing, so a hook holds what it needs through the redemption.
			for (const hook of hooks) {
				try {
					await hook.pin(name);
				} catch (error) {
					await settle(name);
					throw error;
				}
			}
			// The token ends no later than its session, as a refreshed one ends with its family, nor
			// later than the allowance before its record's end.
			const allowed = await issue(accessOf(record, client.id), {
				session: record.session,
				notAfter: Math.min(entry.endsAt, tokenEnd),
			});
			if (allowed.kind === "refused") return allowed;
			const issued = allowed.access;
			const given = { reference: referenceOf(issued), expiresAt: issued.expiresAt };
			// Noted on its record, which keeps its end; one gone meanwhile (erased) gets no token answered.
			const after = await noteToken(redemptionRecords, name, given);
			// TODO(0.22): noted on the code too, keeping its end (never the arbiter), so a 0.19 instance
			// that takes a reuse while the code lives finds the token; what is left is on
			// `redemption-record`'s card.
			const coded = await store.update(name, (stored) => {
				const r = fromStored(stored);
				return r && changed({ ...r, token: given });
			});
			const left = coded && fromStored(coded.after);
			// A code whose record ended meanwhile is refused here, as one gone (erased) is: no hook is
			// told of a code that is gone, as a hook's pin relies on.
			if (!after || !left) return refused;
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
			// TODO(0.22): stop reading `left.void`; until then, a 0.19 instance's reuse marks the code alone.
			if (after.void || left.void || !(await enters(record.session))) {
				await settle(name);
				return refused;
			}
			const maker = idToken && record.scope.includes(idToken.scope) ? idToken : undefined;
			const id =
				maker && (await voidIfFails(() => maker.make(idTokenRequest(record, client.id, name))));
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
			for (const hook of hooks) await voidIfFails(() => hook.redeemed(redeemed));
			return {
				kind: "issued",
				body: {
					...added,
					...(id ? { id_token: id } : {}),
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					scope: record.scope.join(" "),
				},
			};
		},
	};
}
