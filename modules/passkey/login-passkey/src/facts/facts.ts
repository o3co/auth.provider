import type { BuildContext } from "@mod/kernel";
import { loginSource } from "@mod/login-attributes";
import { secondFactorAmr } from "@mod/mfa-extensions";
import { acceptedAttributes, type Users, users } from "@mod/users";
import type { Settings } from "../section.ts";

/** The amr a passkey login proves: `pop`, and the second factor's where the user was verified and it counts. */
export const amrOf = (userVerified: boolean, countsAsMfa: boolean): readonly string[] =>
	userVerified && countsAsMfa ? ["pop", secondFactorAmr] : ["pop"];

/** What an assertion proved. */
export interface Asserted {
	readonly subject: string;
	readonly challengedAt: number;
	readonly userVerified: boolean;
}

/** The login's facts for what an assertion proved, the user's attributes from `users`; none for a subject it does not know. */
export function factsOver(p: {
	readonly users: Pick<Users, "bySubject">;
	readonly countsAsMfa: boolean;
}) {
	return async (asserted: Asserted) => {
		const known = await p.users.bySubject(asserted.subject);
		if (known.kind !== "user") return known;
		const facts = {
			subject: asserted.subject,
			amr: amrOf(asserted.userVerified, p.countsAsMfa),
			// Authenticated here, so as fresh as the session it opens, however long a gate holds it first.
			authenticatedAt: "opening" as const,
			attributes: { source: loginSource.users, values: acceptedAttributes(known.user.attributes) },
		};
		return { kind: "facts" as const, facts };
	};
}

/** What `factsIn` takes from the build context. */
export const factsTakes = [users] as const;

export const factsIn = async (c: BuildContext<Settings>) =>
	factsOver({ users: await c.get(users), countsAsMfa: c.section["counts-as-mfa"] });
