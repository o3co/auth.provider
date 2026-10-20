import { clientAllowance } from "@mod/client-allowance";
import type { TokenTie } from "@mod/grants";
import { type BuildContext, Unavailable } from "@mod/kernel";
import type { FamilyHandle, Lineage } from "../contract.ts";
import { refreshGrantType } from "../contract.ts";
import type { founding } from "../grant/found.ts";
import { foundingIn } from "../grant/grant.ts";
import { fromStoredLink, liveFamily } from "../record.ts";
import type { Settings } from "../section.ts";
import type { Revoker, Stores } from "../settle/settle.ts";
import { familyStore, tokenFamilies } from "../store.ts";

/** A handle names the token it was asked for, so a family's own name never leaves refresh. */
const handleOf = (tokenId: string) => tokenId as unknown as FamilyHandle;
const tokenOf = (family: FamilyHandle) => family as unknown as string;

/** The family a token was issued from, and whether a family has ended, from the stores alone. */
export function familyReader(
	stores: Pick<Stores, "tokenFamilies" | "families">,
	now: () => number,
) {
	const familyOf = async (tokenId: string) => {
		const stored = await stores.tokenFamilies.read(tokenId);
		if (stored === undefined) return undefined;
		const link = fromStoredLink(stored);
		if (!link) throw new Unavailable("refresh");
		return link.family;
	};
	/** A family that has not ended; one revoked, past its end or lost has. */
	const unended = async (id: string) => {
		const family = liveFamily(await stores.families.read(id));
		return family && family.expiresAt > now() ? family : undefined;
	};
	return { familyOf, unended };
}

export function lineageOver(
	stores: Stores,
	revoker: Revoker,
	found: ReturnType<typeof founding>,
	now: () => number,
): Lineage {
	const { familyOf, unended } = familyReader(stores, now);
	return {
		of: async (tokenId) => {
			const id = await familyOf(tokenId);
			if (id === undefined) return { kind: "none" };
			const family = await unended(id);
			if (!family) return { kind: "ended" };
			return { kind: "family", family: handleOf(tokenId), expiresAt: family.expiresAt };
		},
		adopt: async (handle, issued) => {
			const id = await familyOf(tokenOf(handle));
			const family = id === undefined ? undefined : await unended(id);
			if (id === undefined || !family) {
				await revoker.revokeIssued(issued);
				return "ended";
			}
			if (issued.expiresAt > family.expiresAt) {
				await revoker.revokeIssued(issued);
				throw new Error("refresh: an adopted token must end by its family's end");
			}
			await revoker.recordAccess(id, issued);
			// A revocation that listed the family's tokens before this one did not see it: run it again.
			if (!(await unended(id))) {
				await revoker.revokeFamily(id);
				return "ended";
			}
			return "adopted";
		},
		start: async (beginning) => {
			const { client, access } = beginning;
			if (!clientAllowance.allowsGrant(client, refreshGrantType)) return undefined;
			const binding = found.bindingFor(client, beginning.binding);
			const founded = {
				clientId: client.id,
				subject: beginning.subject,
				scope: beginning.scope,
				audience: beginning.audience,
				authenticatedAt: beginning.authenticatedAt,
				...(beginning.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
				amr: beginning.amr,
				...(beginning.acr ? { acr: beginning.acr } : {}),
				...(binding ? { binding } : {}),
			};
			return found.found(found.name(), founded, access);
		},
	};
}

/** The lineage over the contracts the assembly gives. */
export async function lineageIn(c: BuildContext<Settings>) {
	const { stores, revoker, found } = await foundingIn(c);
	return lineageOver(stores, revoker, found, c.clock.now);
}

/** The `family` tie: a token's family as `of` answers it; a token issued from it is adopted. */
export const familyTie = (families: Pick<Lineage, "of" | "adopt">): TokenTie => ({
	name: "family",
	tieOf: async (tokenId) => {
		const found = await families.of(tokenId);
		if (found.kind === "none") return { kind: "none" };
		if (found.kind === "ended") return { kind: "ended", reason: "family has ended" };
		return {
			kind: "held",
			ends: found.expiresAt,
			join: async (issued) => (await families.adopt(found.family, issued)) === "adopted",
		};
	},
});

/** tokens' access condition: an access token of an ended family no longer holds. Built on the stores alone, as tokens asks it while it is being built itself. */
export async function conditionOver(c: BuildContext<Settings>) {
	const stores = { tokenFamilies: await c.get(tokenFamilies), families: await c.get(familyStore) };
	const { familyOf, unended } = familyReader(stores, c.clock.now);
	return {
		name: "refresh-families",
		holds: async ({ id }: { readonly id: string }) => {
			const family = await familyOf(id);
			return family !== undefined && !(await unended(family))
				? ("revoked" as const)
				: ("holds" as const);
		},
	};
}
