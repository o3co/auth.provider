import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import { clientAllowance } from "@mod/client-allowance";
import type { Grant, GrantOutcome } from "@mod/grants";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { sameBinding } from "@mod/sender-binding";
import { type Sessions, sessions } from "@mod/session";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import events from "../audit-events.ts";
import { refreshGrantType } from "../contract.ts";
import { type Random, text } from "../founding/found.ts";
import { type Family, hashOf, liveFamily, parseToken, toStored } from "../record.ts";
import type { Settings } from "../section.ts";
import { type Revoker, type Stores, settlingIn } from "../settle/settle.ts";

/** One answer for every refused token, so it tells nothing about why. */
const refused: GrantOutcome = {
	kind: "error",
	error: "invalid_grant",
	description: "invalid refresh_token",
};

export interface Checks {
	readonly sessions: Sessions;
	readonly revocation: SubjectRevocation;
}

/** This round's access token scope: what is asked, or the family's when none is; none when malformed or wider. */
function scopeFor(asked: string | undefined, granted: readonly string[]) {
	const named = clientAllowance.parseScope(asked);
	const asking = named?.length === 0 ? granted : named;
	if (!asking || asking.some((s) => !granted.includes(s))) return undefined;
	return [...new Set(asking)];
}

/** When the family's next access token must end by; none when the family may no longer be used. */
async function stillValid(family: Family, checks: Checks): Promise<number | undefined> {
	// Only a session that enters at use keeps its family: one closed, ended or short of a requirement does not.
	let endsAt = family.expiresAt;
	if (family.session !== undefined) {
		const entry = await checks.sessions.entryOf(family.session);
		if (entry.kind !== "entered") return undefined;
		endsAt = Math.min(endsAt, entry.endsAt);
	}
	const valid = (await checks.revocation.check(family.subject, family.authenticatedAt)) === "valid";
	return valid ? endsAt : undefined;
}

export interface GrantParts {
	readonly stores: Stores;
	readonly revoker: Revoker;
	readonly checks: Checks;
	readonly random: Random;
	readonly issuer: string;
	readonly now: () => number;
	readonly recorder: Pick<Audit, "record">;
	readonly selections: Pick<ClaimsSelections, "forRefreshed">;
}

export function refreshGrant({
	stores,
	revoker,
	checks,
	random,
	issuer,
	now,
	recorder,
	selections,
}: GrantParts): Grant {
	const recorded = declaredAudit(recorder, events);
	/** Ends the family a reuse showed, and records it. */
	const reused = async (id: string, family: Family) => {
		await revoker.revokeFamily(id);
		recorded.record("refresh.family_revoked", {
			subject: family.subject,
			attributes: { client: family.clientId },
		});
	};
	return {
		grantType: refreshGrantType,
		readsAmbient: "none",
		targets: true,
		handle: async ({ client, param, binding, issue, target }) => {
			const token = param("refresh_token");
			if (!token) {
				return {
					kind: "error",
					error: "invalid_request",
					description: "refresh_token is required",
				};
			}
			const parsed = parseToken(token);
			if (!parsed) return refused;
			const family = liveFamily(await stores.families.read(parsed.id));
			if (!family || family.expiresAt <= now()) return refused;
			if (family.clientId !== client.id) return refused;
			// Knowing a family's name means having held one of its tokens, so any other secret is a
			// reuse, whatever binding comes with it.
			if (hashOf(parsed.secret) !== family.current) {
				await reused(parsed.id, family);
				return refused;
			}
			if (family.binding && !sameBinding(family.binding, binding)) return refused;
			const scope = scopeFor(param("scope"), family.scope);
			if (!scope) return { kind: "error", error: "invalid_scope" };
			const asked = target(
				family.audience,
				(a) => family.audience.includes(a) && clientAllowance.allowsAudience(client, a, issuer),
			);
			if (asked.kind === "error") return asked;
			const { audience } = asked;
			if (!clientAllowance.covers(client, { scope, audience }, issuer)) return refused;
			const notAfter = await stillValid(family, checks);
			if (notAfter === undefined) return refused;
			const next = text(random, 32);
			// Only this access token is narrowed: the family keeps the original grant (RFC 6749 §6).
			const rotated: Family = { ...family, current: hashOf(next) };
			// Everything that can fail comes first, the issuance policies' judgement included: after the
			// rotation, a resend would be taken as reuse. An access token issued here but never answered
			// reaches no one, so it is harmless.
			const judged = await issue(
				{
					subject: family.subject,
					issuedTo: client.id,
					audience,
					scope,
					amr: family.amr,
					authenticatedAt: family.authenticatedAt,
					...(family.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
					...(family.acr ? { acr: family.acr } : {}),
					// Bound to no session, the token stands from the authentication its boundary was compared with.
					...(family.session ? {} : { standingAt: family.authenticatedAt }),
				},
				// A refresh continues a grant the policies already let through: they may judge it so.
				{
					notAfter,
					continuing: true,
					...(family.session ? { session: family.session } : {}),
				},
			);
			if (judged.kind === "refused") return judged;
			const issued = judged.access;
			await revoker.recordAccess(parsed.id, issued);
			// The family's selection, its names cut to what is allowed and agreed to now, kept for this token;
			// failing, the token is revoked and the round fails before the rotation, so it can be tried again.
			try {
				await selections.forRefreshed(parsed.id, client, family.subject, issued);
			} catch (error) {
				await revoker.revokeIssued(issued);
				throw error;
			}
			// A boundary or a logout that came while the token was made: its session no longer enters, and
			// the token, standing from its issue, is withdrawn rather than handed out.
			if (family.session !== undefined) {
				const entry = await checks.sessions.entryOf(family.session);
				if (entry.kind !== "entered") {
					await revoker.revokeIssued(issued);
					return refused;
				}
			}
			// Rotates only from the secret checked here, however often the change runs again.
			const written = await stores.families.update(parsed.id, (stored) =>
				liveFamily(stored)?.current === family.current ? { value: toStored(rotated) } : undefined,
			);
			// Another use, a revocation or a logout came first: a reuse, or a family already ended.
			const after = liveFamily(written?.after);
			if (after?.current !== rotated.current) {
				if (after) await reused(parsed.id, family);
				else await revoker.revokeFamily(parsed.id);
				return refused;
			}
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					refresh_token: `${parsed.id}.${next}`,
					scope: scope.join(" "),
				},
			};
		},
	};
}

/** What `grantOver` takes beside `settlingIn`'s. */
export const grantTakes = [sessions, subjectRevocation, issuer, audit, claimsSelections];

/** The refresh_token grant over the contracts the assembly gives; it sweeps the families to settle. */
export async function grantOver(c: BuildContext<Settings>) {
	const { stores, revoker } = await settlingIn(c);
	c.every(c.section["sweep-interval"] * 1000, () => revoker.sweep());
	const checks = { sessions: await c.get(sessions), revocation: await c.get(subjectRevocation) };
	return refreshGrant({
		stores,
		revoker,
		checks,
		random: c.random.bytes,
		issuer: (await c.get(issuer)).url,
		now: c.clock.now,
		recorder: await c.get(audit),
		selections: await c.get(claimsSelections),
	});
}
