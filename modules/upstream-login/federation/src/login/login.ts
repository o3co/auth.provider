import { type Audit, audit } from "@mod/audit";
import { jsonAnswer, noStore, site } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { loginSource } from "@mod/login-attributes";
import { type Logins, logins } from "@mod/login-gates";
import { type Handoff, handoff } from "@mod/upstream-handoff";
import type { UpstreamLogin } from "@mod/upstreams";
import { type Users, userAttribute, users } from "@mod/users";
import {
	type Continuation,
	type Idp,
	landingIn,
	proves,
	recorderOf,
	secondOf,
	sent,
} from "../round-trip/round-trip.ts";
import type { Settings } from "../section.ts";

export interface LoginParts {
	readonly logins: Pick<Logins, "login">;
	readonly users: Pick<Users, "byUpstream">;
	readonly audit: Pick<Audit, "record">;
	readonly handoff: Pick<Handoff, "of">;
	readonly landing: string;
	readonly heldLoginLifetimeMs: number;
	readonly heldPage?: string | undefined;
}

/** The name login-gates tells when a login federation asked for opens after a hold. */
export const loginCaller = "federation";

export async function loginIn(c: BuildContext<Settings>): Promise<Continuation> {
	const heldPage = c.section["held-page"];
	if (heldPage !== undefined && new URL(heldPage).origin !== (await c.get(site)).origin) {
		c.refuse("federation.held-page", "not on the public origin");
	}
	return loginWith({
		logins: await c.get(logins),
		users: await c.get(users),
		audit: await c.get(audit),
		handoff: await c.get(handoff),
		landing: await landingIn(c),
		heldLoginLifetimeMs: c.section["transaction-lifetime"] * 1000,
		heldPage,
	});
}

/** The login a round trip ends in: the local user the upstream identity is linked to, handed to `login-gates`. */
export function loginWith(p: LoginParts): Continuation {
	const record = recorderOf(p.audit, "federation.login");
	return {
		begin: async () => ({}),
		failed: ({ name, reason, source }) => record("failed", name, { reason, source }),
		complete: async ({ request, name, idp, upstreamLogin, trip, source, cleared }) => {
			const found = await p.users.byUpstream(name, upstreamLogin.subject);
			if (found.kind !== "user") {
				record("failed", name, { reason: "unknown_user", source });
				return jsonAnswer(401, { error: "unknown_user" }, { cookies: cleared });
			}
			const mapped = upstreamLogin.amr.flatMap((value) => idp.upstreamAmr.get(value) ?? []);
			const amr = [...new Set([...proves, ...mapped])];
			const lands = trip.redirectTo ?? p.landing;
			const done = { redirect_to: lands };
			const subject = found.user.subject;
			const handing = p.handoff.of(name, subject, upstreamLogin.tokens, p.heldLoginLifetimeMs);
			const from = handing && {
				caller: loginCaller,
				carry: handing.carry,
				deadline: handing.deadline,
			};
			const authenticatedAt = onOurClock(upstreamLogin.authenticatedAt, trip.startedAt, idp);
			const facts = { subject, amr, authenticatedAt, ...attributesOf(name, upstreamLogin.profile) };
			const outcome = await p.logins.login(request, facts, done, from);
			await handing?.after(outcome);
			// A login a gate refused fails as one with no local user does, telling nothing of why.
			if (outcome.kind === "refused") {
				record("failed", name, { reason: "refused", source });
				return jsonAnswer(401, { error: "unknown_user" }, { cookies: cleared });
			}
			const held = outcome.kind === "held";
			record(held ? "held" : "succeeded", name, { subject, source });
			const cookies = [...cleared, ...outcome.cookies];
			if (!held) return sent(lands, cookies);
			return p.heldPage === undefined
				? jsonAnswer(403, outcome.answer, { cookies })
				: { status: 303, headers: { ...noStore, location: p.heldPage }, cookies };
		},
	};
}

/**
 * When the upstream says the user logged in, on our clock: a time before the start but within the
 * upstream's clock allowance before the start's second was the round trip's own login: the start.
 */
function onOurClock(at: number | undefined, startedAt: number, idp: Idp) {
	if (at === undefined) return "unknown" as const;
	return at < startedAt && at + (idp.upstream.clockSkewMs ?? 0) >= secondOf(startedAt)
		? startedAt
		: at;
}

/**
 * The upstream's profile as the session keeps it, under the IdP's name and by users' attribute
 * names. Read here, not passed on: the email is verified only where the type says so, and an
 * upstream never names groups.
 */
function attributesOf(idp: string, profile: UpstreamLogin["profile"]) {
	if (profile === undefined) return {};
	const { email, emailVerified, name, picture } = profile;
	const values = {
		...(typeof email === "string"
			? { email, [userAttribute.emailVerified]: emailVerified === true }
			: {}),
		...(typeof name === "string" ? { name } : {}),
		...(typeof picture === "string" ? { picture } : {}),
	};
	return { attributes: { source: loginSource.upstream(idp), values } };
}
