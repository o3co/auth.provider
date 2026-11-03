import type { Client } from "@mod/clients";
import { canBeAgreed, type Consents, consents, isFirstParty } from "@mod/consent";
import type { BuildContext } from "@mod/kernel";
import type { Session } from "@mod/session";
import { type Again, type Decision, recorded, refusal } from "../decision.ts";
import type { Settings } from "../section.ts";

export interface ConsentDecision {
	/** A request that comes back from a denial on the consent page is refused. */
	denied(one: (name: string) => string | undefined): Decision | undefined;
	/** A client that is not first-party is refused while consent cannot ask, or where no grant could ever count for it. */
	served(client: Client): Decision | undefined;
	/** Whether the subject agreed to the client for one scope: always, for a first-party client. */
	consented(client: Client, subject: string, scope: string): Promise<boolean>;
	/** Nothing when the code may be issued; otherwise a refusal, or the consent page. Asked after `served`. */
	decide(
		client: Client,
		session: Session,
		scope: readonly string[],
		prompt: ReadonlySet<string>,
		again: Again,
	): Promise<Decision | undefined>;
}

export interface ConsentDecisionParts {
	readonly consents: Pick<Consents, "coversFor" | "askFor" | "asking">;
}

const notServed = "client is not authorized for the authorization endpoint";

export function consentDecisionWith({ consents: kept }: ConsentDecisionParts): ConsentDecision {
	return {
		denied: (one) => (one("consent_denied") === "1" ? refusal("access_denied") : undefined),
		served: (client) => {
			if (isFirstParty(client)) return undefined;
			// Without a page to ask on, a client that is not first-party is never served.
			if (!kept.asking) return recorded("unauthorized_client", "client_not_first_party", notServed);
			// No answer could ever cover it: asked, the browser would come back to be asked again, for ever.
			return canBeAgreed(client)
				? undefined
				: recorded("unauthorized_client", "client_agreed_under_nothing", notServed);
		},
		consented: async (client, subject, scope) =>
			isFirstParty(client) || (await kept.coversFor(client, subject, [scope])),
		async decide(client, session, scope, prompt, again) {
			if (isFirstParty(client)) return undefined;
			const asked =
				prompt.has("consent") || !(await kept.coversFor(client, session.context.subject, scope));
			if (!asked) return undefined;
			if (prompt.has("none")) return recorded("consent_required", "consent_required");
			const page = await kept.askFor(session, client, {
				range: scope,
				onAccept: again(["reauth", "prompt:login", "prompt:consent"]),
				onDeny: again(["reauth"], [["consent_denied", "1"]]),
			});
			return { kind: "send", to: page };
		},
	};
}

/** What `consentDecisionOver` takes. */
export const consentDecisionTakes = [consents];

/** The decision over `consent`'s records the assembly gives. */
export const consentDecisionOver = async (c: BuildContext<Settings>) =>
	consentDecisionWith({ consents: await c.get(consents) });
