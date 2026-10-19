import { clientAllowance } from "@mod/client-allowance";
import type { Redeemed } from "@mod/code-grant";
import type { Grant, GrantOutcome } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { type BuildContext, type Log, Unavailable } from "@mod/kernel";
import { sameBinding } from "@mod/sender-binding";
import { type Sessions, sessions } from "@mod/session";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { refreshGrantType } from "../contract.ts";
import {
	allowanceMs,
	type Family,
	fromStoredRedemption,
	hashOf,
	liveFamily,
	parseToken,
	toStored,
	toStoredRedemption,
} from "../record.ts";
import type { Settings } from "../section.ts";
import { type Revoker, type Stores, settlingIn } from "../settle/settle.ts";
import { founding, type Random, text } from "./found.ts";

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

async function stillValid(family: Family, checks: Checks) {
	// Only a session that enters at use keeps its family: one closed, ended or short of a requirement does not.
	if (
		family.session !== undefined &&
		(await checks.sessions.entryOf(family.session)).kind !== "entered"
	) {
		return false;
	}
	return (await checks.revocation.check(family.subject, family.authenticatedAt)) === "valid";
}

export function starting(
	stores: Stores,
	revoker: Revoker,
	found: ReturnType<typeof founding>,
	lifetimeMs: number,
	log: Log,
) {
	return async (redeemed: Redeemed) => {
		if (!clientAllowance.allowsGrant(redeemed.client, refreshGrantType)) return undefined;
		const id = found.name();
		const binding = found.bindingFor(redeemed.client, redeemed.binding);
		// Both writes come before the family's record. Named for its redemption: a code that comes
		// again finds it, or has already marked that none may start.
		const named = toStoredRedemption({ format: 1, family: id });
		const redemptionMs = lifetimeMs + allowanceMs;
		if ((await stores.redemptions.save(redeemed.redemption, named, redemptionMs)) !== "created") {
			throw new Unavailable("refresh");
		}
		// Listed under its session: a close that comes meanwhile finds and revokes it.
		const { pushedOut } = await stores.sessionFamilies.add(redeemed.session, id, lifetimeMs);
		// A family dropped from its session's list would outlive the session: it ends instead.
		if (pushedOut.length > 0) {
			log.error("refresh.session_list_pushed_out", { count: pushedOut.length });
			for (const dropped of pushedOut) await revoker.revokeFamily(dropped);
			throw new Unavailable("refresh");
		}
		return found.found(
			id,
			{
				clientId: redeemed.client.id,
				subject: redeemed.subject,
				scope: redeemed.scope,
				audience: redeemed.audience,
				session: redeemed.session,
				authenticatedAt: redeemed.authenticatedAt,
				...(redeemed.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
				amr: redeemed.amr,
				...(redeemed.acr ? { acr: redeemed.acr } : {}),
				...(binding ? { binding } : {}),
			},
			redeemed.access,
		);
	};
}

export function refreshGrant(
	stores: Stores,
	revoker: Revoker,
	checks: Checks,
	random: Random,
	issuer: string,
	now: () => number,
): Grant {
	return {
		grantType: refreshGrantType,
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
				await revoker.revokeFamily(parsed.id);
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
			if (!(await stillValid(family, checks))) return refused;
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
				},
				// A refresh continues a grant the policies already let through: they may judge it so.
				{
					notAfter: family.expiresAt,
					continuing: true,
					...(family.session ? { session: family.session } : {}),
				},
			);
			if (judged.kind === "refused") return judged;
			const issued = judged.access;
			await revoker.recordAccess(parsed.id, issued);
			// Rotates only from the secret checked here, however often the change runs again.
			const written = await stores.families.update(parsed.id, (stored) =>
				liveFamily(stored)?.current === family.current ? { value: toStored(rotated) } : undefined,
			);
			// Another use, a revocation or a logout came first: a reuse, or a family already ended.
			if (liveFamily(written?.after)?.current !== rotated.current) {
				await revoker.revokeFamily(parsed.id);
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

/** Ends the family a redemption started; with none yet, marks that none may start. */
export function takingBack(stores: Stores, revoker: Revoker, lifetimeMs: number) {
	return async (redemption: string) => {
		const mark = toStoredRedemption({ format: 1, taken: true });
		await stores.redemptions.save(redemption, mark, lifetimeMs + allowanceMs);
		// save keeps whichever came first; read back to see which.
		const stored = await stores.redemptions.read(redemption);
		if (stored === undefined) return;
		const left = fromStoredRedemption(stored);
		if (!left) throw new Unavailable("refresh");
		if ("family" in left) await revoker.revokeFamily(left.family);
	};
}

/** The founding of families over the contracts the assembly gives. */
export async function foundingIn(c: BuildContext<Settings>) {
	const { stores, revoker, lifetimeMs } = await settlingIn(c);
	const bindConfidential = c.section["bind-confidential-clients"];
	const found = founding(
		stores,
		revoker,
		lifetimeMs,
		c.random.bytes,
		c.clock.now,
		bindConfidential,
	);
	return { stores, revoker, lifetimeMs, found };
}

/** The refresh_token grant over the contracts the assembly gives; it sweeps the families to settle. */
export async function grantOver(c: BuildContext<Settings>) {
	const { stores, revoker } = await settlingIn(c);
	c.every(c.section["sweep-interval"] * 1000, () => revoker.sweep());
	const checks = { sessions: await c.get(sessions), revocation: await c.get(subjectRevocation) };
	const issuerUrl = (await c.get(issuer)).url;
	return refreshGrant(stores, revoker, checks, c.random.bytes, issuerUrl, c.clock.now);
}

/** code-grant's addition of a refresh token to an exchanged code. */
export async function additionOver(c: BuildContext<Settings>) {
	const { stores, revoker, lifetimeMs, found } = await foundingIn(c);
	return {
		field: "refresh_token",
		revoke: takingBack(stores, revoker, lifetimeMs),
		issue: starting(stores, revoker, found, lifetimeMs, c.log),
	};
}
