import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import { clientAllowance } from "@mod/client-allowance";
import type { Redeemed } from "@mod/code-grant";
import { type BuildContext, type Log, Unavailable } from "@mod/kernel";
import { refreshGrantType } from "../contract.ts";
import { allowanceMs, fromStoredRedemption, toStoredRedemption } from "../record.ts";
import type { Settings } from "../section.ts";
import { type Revoker, type Stores, settlingIn } from "../settle/settle.ts";
import { founding } from "./found.ts";

export function starting(
	stores: Stores,
	revoker: Revoker,
	found: ReturnType<typeof founding>,
	lifetimeMs: number,
	log: Log,
	selections: Pick<ClaimsSelections, "follow">,
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
		// The family keeps what its code's request asked beyond its scope; failing, the code is voided.
		await selections.follow(redeemed.redemption, id, lifetimeMs + allowanceMs);
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

/** code-grant's addition of a refresh token to an exchanged code. */
export async function additionOver(c: BuildContext<Settings>) {
	const { stores, revoker, lifetimeMs, found } = await foundingIn(c);
	return {
		field: "refresh_token",
		revoke: takingBack(stores, revoker, lifetimeMs),
		issue: starting(stores, revoker, found, lifetimeMs, c.log, await c.get(claimsSelections)),
	};
}
