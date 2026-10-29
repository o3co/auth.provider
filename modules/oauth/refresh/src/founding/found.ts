import type { Client } from "@mod/clients";
import { Unavailable } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import { allowanceMs, type Family, hashOf, liveFamily, toStored } from "../record.ts";
import type { Revoker, Stores } from "../settle/settle.ts";

export type Random = (n: number) => Uint8Array;
export const text = (random: Random, n: number) => Buffer.from(random(n)).toString("base64url");

/** What a new family holds besides its secret and its end. */
export type Founded = Omit<Family, "format" | "current" | "expiresAt">;

export function founding(
	stores: Stores,
	revoker: Revoker,
	lifetimeMs: number,
	random: Random,
	now: () => number,
	bindConfidential: boolean,
) {
	return {
		name: () => text(random, 16),
		/** The binding a new family takes: a public client's, and a confidential one's where bound too. */
		bindingFor: (client: Client, binding: Binding | undefined) =>
			client.kind === "public" || bindConfidential ? binding : undefined,
		/** When a family started now ends: read once, so all that is kept for it ends by the same time. */
		endsAt: () => now() + lifetimeMs,
		/** Writes a named family ending at `expiresAt` and remembers its first access token; answers its first refresh token. */
		found: async (
			id: string,
			founded: Founded,
			access: { id: string; expiresAt: number },
			expiresAt: number,
		) => {
			const first = text(random, 32);
			const at = now();
			const family: Family = {
				format: 2,
				current: hashOf(first),
				...founded,
				expiresAt,
			};
			// Kept while what it issued lives, so revoking its token still revokes them once it expired.
			const familyMs = Math.max(lifetimeMs, access.expiresAt - at) + allowanceMs;
			if ((await stores.families.save(id, toStored(family), familyMs)) !== "created") {
				throw new Unavailable("refresh");
			}
			await revoker.recordAccess(id, access);
			// Read back by a change, as rotation does: a revocation that came meanwhile, its cap's
			// push-out say, issues nothing, and its token is revoked with the family.
			const written = await stores.families.update(id, (stored) =>
				liveFamily(stored)?.current === family.current ? { value: stored } : undefined,
			);
			if (liveFamily(written?.after)?.current !== family.current) {
				await revoker.revokeFamily(id);
				throw new Unavailable("refresh");
			}
			return `${id}.${first}`;
		},
	};
}
