import type { Delegation } from "@mod/upstreams";
import type { Back, GrantIntents } from "../../browser.ts";

/** A stand-in step's answer, as a browser sees one: a redirect, or a refusal. */
export interface Walked {
	readonly status: number;
	readonly headers: Record<string, string>;
	readonly cookies: readonly string[];
}

/**
 * A stand-in for the browser half over `grantIntents` alone: it walks an intent through its link,
 * question, upstream start and return as a browser half would, without the browser half's own
 * checks (session entry, round trips, the upstream account).
 */
export function browserStandIn(
	intents: GrantIntents,
	p: {
		readonly delegation: Delegation;
		/** The page that asks the user. */
		readonly page: string;
		/** What the upstream answers a code with: a login with its issuer, subject and tokens. */
		readonly exchange: (code: string) => Promise<unknown>;
	},
) {
	const seeing = (location: string): Walked => ({
		status: 303,
		headers: { location },
		cookies: [],
	});
	const refused: Walked = { status: 400, headers: {}, cookies: [] };
	const backOf = (to: Back) => (to.kind === "back" ? seeing(to.location) : refused);
	/** What each upstream state carries, as a round trip keeps it until its return takes it. */
	const trips = new Map<string, unknown>();
	let started = 0;
	return {
		/** Opens a link in the session named, binding the intent to it: the answer, and the challenge. */
		open: async (handle: string, session: string | undefined) => {
			const linked = await intents.linked(handle);
			const bound =
				linked.kind === "linked" && session ? await intents.bound(linked.ref, session) : undefined;
			const challenge = bound?.kind === "bound" ? bound.challenge : "";
			return {
				opened: challenge ? seeing(`${p.page}?challenge=${challenge}`) : refused,
				challenge,
			};
		},
		/** Decides a question: denied, or accepted once the upstream start is built; the answer, and the upstream state. */
		decide: async (challenge: string, decision = "accept") => {
			const asked = await intents.asked(challenge);
			if (asked.kind !== "asked") return { answered: refused, state: "" };
			if (decision === "deny") {
				const denied = await intents.denied(asked.ref, challenge, {});
				return { answered: denied.kind === "invalid" ? refused : backOf(denied), state: "" };
			}
			const start = intents.starting(asked.ref);
			if (!start) return { answered: refused, state: "" };
			const state = `state-${++started}`;
			const url = p.delegation.authorizationUrl({
				state,
				nonce: "nonce",
				challenge: "pkce",
				challengeMethod: "S256",
				redirectUri: start.redirectUri,
				scopes: start.scopes,
				...(start.resource ? { resource: start.resource } : {}),
			});
			if (!(await intents.accepted(challenge))) return { answered: refused, state: "" };
			trips.set(state, start.carried);
			return { answered: seeing(String(url)), state };
		},
		/** The upstream's return with `state`, taken once: resumed, checked again, its tokens judged, and activated. */
		callback: async (state: string, code: string): Promise<Walked> => {
			const carried = trips.get(state);
			trips.delete(state);
			if (carried === undefined) return refused;
			const resumed = await intents.resumed(carried);
			if (resumed.kind === "stale") return refused;
			if (resumed.kind === "unconfigured")
				return backOf(await intents.failed(resumed.ref, "grant_not_authorizable", {}));
			const { ref } = resumed;
			const revoked = await intents.stillValid(ref);
			if (revoked) return backOf(await intents.failed(ref, revoked, {}));
			const login = (await p.exchange(code)) as Record<string, unknown>;
			const judged = intents.judged(ref, login.tokens);
			if (judged.kind === "refused") return backOf(await intents.failed(ref, judged.why, {}));
			const upstream = { issuer: String(login.issuer), subject: String(login.subject) };
			const identityCheck = "required";
			return backOf(
				await intents.activated(ref, { upstream, tokens: judged.tokens, identityCheck }),
			);
		},
	};
}
