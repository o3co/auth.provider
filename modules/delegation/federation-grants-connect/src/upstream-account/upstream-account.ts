import type { UpstreamAccount } from "@mod/federation-grants";
import type { BuildContext } from "@mod/kernel";
import { type Users, users } from "@mod/users";
import type { Settings } from "../section.ts";

export type { UpstreamAccount };

/** Why a connection's upstream account is not one the grant's subject may connect. */
export type AccountRefusal = "account_mismatch" | "identity_unverifiable" | "identity_conflict";

export interface UpstreamAccountParts {
	readonly users: Pick<Users, "byUpstream">;
	readonly check: Settings["identity-check"];
}

/** Whose upstream account a connection reached: the grant's, as its record and intent expect, and by the identity check. */
export function upstreamAccountWith(p: UpstreamAccountParts) {
	return {
		/** The identity check made, as an activation's audit names it. */
		check: p.check,
		/** Why `reached`, at `idp`, is not one the grant's subject may connect; none where it is. */
		refusal: async (
			grant: { readonly subject: string; readonly upstream?: UpstreamAccount | undefined },
			intent: { readonly expectedUpstream?: string | undefined },
			idp: string,
			reached: UpstreamAccount,
		): Promise<AccountRefusal | undefined> => {
			const known = grant.upstream;
			if (known && (known.issuer !== reached.issuer || known.subject !== reached.subject)) {
				return "account_mismatch";
			}
			if (intent.expectedUpstream !== undefined && intent.expectedUpstream !== reached.subject) {
				return "account_mismatch";
			}
			if (p.check !== "required") return undefined;
			// Any failure of the ledger reads as unverifiable, unavailable or not.
			const found = await p.users.byUpstream(idp, reached.subject).catch(() => undefined);
			if (found === undefined) return "identity_unverifiable";
			return found.kind === "user" && found.user.subject !== grant.subject
				? "identity_conflict"
				: undefined;
		},
	};
}

export type UpstreamAccounts = ReturnType<typeof upstreamAccountWith>;

/** The upstream account check over the users the assembly gives and the identity check in force. */
export const upstreamAccountOver = async (
	c: BuildContext<unknown>,
	check: Settings["identity-check"],
) => upstreamAccountWith({ users: await c.get(users), check });
