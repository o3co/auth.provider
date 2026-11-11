import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import { clientAllowance } from "@mod/client-allowance";
import type { Redeemed } from "@mod/code-grant";
import { type BuildContext, Unavailable } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { refreshGrantType } from "../contract.ts";
import { allowanceMs, fromStoredRedemption, toStoredRedemption } from "../record.ts";
import type { Settings } from "../section.ts";
import { type Revoker, type Stores, settlingIn } from "../settle/settle.ts";
import { familyFieldsOf, founding } from "./found.ts";

export function starting(
	stores: Stores,
	revoker: Revoker,
	found: ReturnType<typeof founding>,
	lifetimeMs: number,
	selections: Pick<ClaimsSelections, "follow">,
	entered: Pick<Sessions, "entryOf">,
) {
	return async (redeemed: Redeemed) => {
		if (!clientAllowance.allowsGrant(redeemed.client, refreshGrantType)) return undefined;
		const id = found.name();
		const binding = found.bindingFor(redeemed.client, redeemed.binding);
		// One end, read before the selection is kept: kept from then, it outlives the family by the allowance.
		const expiresAt = found.endsAt();
		// The family keeps what its code's request asked beyond its scope; failing, the code is voided.
		await selections.follow(redeemed.redemption, id, lifetimeMs + allowanceMs);
		// A session closed before the family starts issues nothing, and no record is written.
		if ((await entered.entryOf(redeemed.session)).kind !== "entered") {
			throw new Unavailable("refresh");
		}
		const token = await found.found(
			id,
			familyFieldsOf(redeemed, binding),
			redeemed.access,
			expiresAt,
		);
		// Named for its redemption after the record: the link's create decides every order with a take-back.
		// One taken first answers `exists`, so the family is revoked here and hands out no token.
		const named = toStoredRedemption({ format: 1, family: id });
		const redemptionMs = lifetimeMs + allowanceMs;
		if ((await stores.redemptions.save(redeemed.redemption, named, redemptionMs)) !== "created") {
			await revoker.revokeFamily(id);
			throw new Unavailable("refresh");
		}
		return token;
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
		issue: starting(
			stores,
			revoker,
			found,
			lifetimeMs,
			await c.get(claimsSelections),
			await c.get(sessions),
		),
	};
}
