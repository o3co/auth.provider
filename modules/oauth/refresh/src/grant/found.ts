import type { Client } from "@mod/clients";
import { Unavailable } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import { allowanceMs, type Family, hashOf, toStored } from "../record.ts";
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
		/** Writes a named family and remembers its first access token; answers its first refresh token. */
		found: async (id: string, founded: Founded, access: { id: string; expiresAt: number }) => {
			const first = text(random, 32);
			const at = now();
			const family: Family = {
				format: 2,
				current: hashOf(first),
				...founded,
				expiresAt: at + lifetimeMs,
			};
			// Kept while what it issued lives, so revoking its token still revokes them once it expired.
			const familyMs = Math.max(lifetimeMs, access.expiresAt - at) + allowanceMs;
			if ((await stores.families.save(id, toStored(family), familyMs)) !== "created") {
				throw new Unavailable("refresh");
			}
			await revoker.recordAccess(id, access);
			return `${id}.${first}`;
		},
	};
}
