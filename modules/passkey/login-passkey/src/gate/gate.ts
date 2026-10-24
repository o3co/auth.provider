import type { BuildContext } from "@mod/kernel";
import type { LoginGate } from "@mod/login-gates";
import { type PasskeyHolders, passkeyHolders } from "@mod/passkeys";
import { type Recorded, recordedIn, recordedTakes } from "../audited/audited.ts";
import type { Settings } from "../section.ts";

/**
 * The gate `credential-policy`: where it `refuses`, a password login (amr `pwd`) of a subject holding
 * a passkey is refused, but one in `exempt`; asked again when a login a later gate held resumes.
 * Otherwise it passes every login.
 */
export function credentialPolicy(p: {
	readonly refuses: boolean;
	readonly holders: Pick<PasskeyHolders, "held">;
	readonly recorded: Recorded;
	readonly exempt: string | undefined;
}): LoginGate {
	return {
		name: "credential-policy",
		rechecked: true,
		hold: async (request, facts) => {
			if (!p.refuses || !facts.amr.includes("pwd")) return { kind: "pass" };
			const groups = facts.attributes?.values.groups ?? [];
			if (p.exempt !== undefined && groups.includes(p.exempt)) return { kind: "pass" };
			// Settled with the witness: a store that lost the passkeys reads unavailable, never as none.
			if (!(await p.holders.held(facts.subject))) return { kind: "pass" };
			p.recorded.passwordRefused(request, facts.subject);
			return { kind: "refused" };
		},
	};
}

/** What `gateIn` takes from the build context, its own and the records' it asks. */
export const gateTakes = [passkeyHolders, ...recordedTakes] as const;

export const gateIn = async (c: BuildContext<Settings>) => {
	const refuses = c.section.password === "refused-when-held";
	const holders = await c.get(passkeyHolders);
	// Without a witness a lost passkey store reads as holding none, letting a former holder's password in.
	if (refuses && !holders.witnessed) {
		return c.refuse(
			"login-passkey.password",
			"refused-when-held needs a passkey witness composed: a lost passkey store would read as holding none",
		);
	}
	return credentialPolicy({
		refuses,
		holders,
		recorded: await recordedIn(c),
		exempt: c.section["password-exempt-group"],
	});
};
