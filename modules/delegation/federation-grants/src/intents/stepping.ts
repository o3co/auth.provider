import type { GrantIntents } from "../browser.ts";
import { type Intent, permits } from "../grant/grant.ts";
import type { Common } from "./common.ts";
import { foundOf, refOf } from "./found.ts";

/** The browser's steps of an intent before the upstream: the link, the session raised and bound, the question asked and answered, and the round trip's start. */
export function steppingWith({
	p,
	records,
	connections,
	secret,
	callbackUrl,
	liveIntent,
	changeIntent,
	take,
	failed,
}: Common): Pick<
	GrantIntents,
	| "linked"
	| "permitted"
	| "available"
	| "steppedUp"
	| "bound"
	| "asked"
	| "denied"
	| "starting"
	| "accepted"
> {
	/** The intent's last trip to raise the session, if any. */
	const tripOf = (stepped: Intent["stepped"]) => (stepped === true ? { at: 0 } : stepped);
	/** A trip is due unless the last was for the same requirement, in a login no later than it. */
	const mayStep = (stepped: Intent["stepped"], requirement: string, authenticatedAt: number) => {
		const last = tripOf(stepped);
		return (
			!last ||
			!("requirement" in last) ||
			last.requirement !== requirement ||
			authenticatedAt > last.at
		);
	};
	return {
		linked: async (handle) => {
			const step = records.stepOf(await p.steps.read(handle));
			const found = step?.kind === "link" ? await liveIntent(step) : undefined;
			if (!found) return { kind: "stale" };
			const { grant, intent } = found;
			return {
				kind: "linked",
				ref: refOf(found),
				view: {
					subject: grant.subject,
					client: grant.client,
					connection: grant.connection,
					...(intent.session === undefined ? {} : { session: intent.session }),
				},
			};
		},
		permitted: async (ref) => {
			const { grant } = foundOf(ref);
			return permits(await p.clients.find(grant.client), grant.connection);
		},
		available: async (ref) => {
			const { grant } = foundOf(ref);
			return (
				permits(await p.clients.find(grant.client), grant.connection) &&
				connections.of(grant.connection) !== undefined
			);
		},
		steppedUp: async (ref, requirement, authenticatedAt) => {
			const found = foundOf(ref);
			if (!mayStep(found.intent.stepped, requirement, authenticatedAt)) return false;
			const trip = { requirement, at: p.clock.now() };
			const marked = await changeIntent(found, (i) =>
				mayStep(i.stepped, requirement, authenticatedAt) ? { ...i, stepped: trip } : undefined,
			);
			const before = tripOf(records.grantOf(marked?.before)?.intent?.stepped);
			const after = tripOf(records.grantOf(marked?.after)?.intent?.stepped);
			const ours = (t: typeof after) =>
				t !== undefined &&
				"requirement" in t &&
				t.requirement === trip.requirement &&
				t.at === trip.at;
			return ours(after) && !ours(before);
		},
		bound: async (ref, session) => {
			const found = foundOf(ref);
			const { grant, intent } = found;
			if (intent.session !== undefined && intent.session !== session) return { kind: "stale" };
			const bound = await changeIntent(found, (i) =>
				i.session === undefined ? { ...i, session } : i.session === session ? i : undefined,
			);
			if (records.grantOf(bound?.after)?.intent?.session !== session) return { kind: "stale" };
			const challenge = secret();
			const question = {
				format: 1,
				kind: "question",
				grant: grant.id,
				intent: intent.id,
				session,
			} as const;
			await p.steps.create(
				challenge,
				records.storedStep(question),
				Math.max(1, intent.endsAt - p.clock.now()),
			);
			return { kind: "bound", challenge };
		},
		asked: async (challenge) => {
			const step = records.stepOf(await p.steps.read(challenge));
			const found = step?.kind === "question" && !step.taken ? await liveIntent(step) : undefined;
			if (!step || !found) return { kind: "invalid" };
			const { grant, intent } = found;
			const resource = connections.of(grant.connection)?.resource;
			return {
				kind: "asked",
				ref: refOf(found),
				view: {
					subject: grant.subject,
					client: grant.client,
					connection: grant.connection,
					scopes: intent.scopes,
					...(resource ? { resource } : {}),
					grantLifetimeMs: intent.lifetimeMs,
					expiresInMs: Math.max(0, intent.endsAt - p.clock.now()),
					session: step.session ?? "",
				},
			};
		},
		denied: async (ref, challenge, from) => {
			if (!(await take(challenge, "question"))) return { kind: "invalid" };
			return failed(ref, "access_denied", from);
		},
		starting: (ref) => {
			const { grant, intent } = foundOf(ref);
			const configured = connections.configured(grant.connection);
			if (!configured) return undefined;
			const { resource, idp } = configured.connection;
			return {
				carried: { grant: grant.id, intent: intent.id, session: intent.session ?? "" },
				lifetimeMs: Math.max(1, intent.endsAt - p.clock.now()),
				idp,
				redirectUri: callbackUrl(grant.connection),
				scopes: intent.scopes,
				...(resource ? { resource } : {}),
			};
		},
		accepted: async (challenge) => (await take(challenge, "question")) !== undefined,
	};
}
