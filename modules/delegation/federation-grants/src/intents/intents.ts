import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Clients, clients } from "@mod/clients";
import type { BuildContext, Clock, Log, Random } from "@mod/kernel";
import { type Upstreams, upstreams } from "@mod/upstreams";
import { z } from "zod";
import events from "../audit-events.ts";
import type { Back, GrantIntents, HeldTokens, IntentRef, Sourced } from "../browser.ts";
import {
	type Credentials,
	connectionsIn,
	credentialsFrom,
	type Grant,
	type Intent,
	type Judge,
	type Listing,
	permits,
	type Records,
	retentionMs,
	returnsTo,
	type Step,
	secretFrom,
} from "../grant/grant.ts";
import { shared } from "../grant/shared.ts";
import { connectionName, type Settings } from "../section.ts";
import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	type StepStore,
	stepStore,
} from "../store.ts";

export interface IntentsParts {
	readonly clients: Clients;
	readonly upstreams: Upstreams;
	readonly grants: GrantStore;
	readonly steps: StepStore;
	readonly pending: PendingIntents;
	readonly records: Records;
	readonly judge: Judge;
	readonly listed: Listing;
	readonly audit: Audit;
	readonly settings: Settings;
	readonly origin: string;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
}

/** Where the browser's steps are served, below the public origin. */
export const browserBase = "/session/federation-grants";

/** What a connection's round trip carries for its callback: the grant, its intent and the session that decided. */
const carried = z.strictObject({ grant: z.string(), intent: z.string(), session: z.string() });

/** A ref as the browser half holds it: the grant and its intent as read. */
interface Found {
	readonly grant: Grant;
	readonly intent: Intent;
}
const refOf = (found: Found) => Object.freeze({ ...found }) as unknown as IntentRef;
const foundOf = (ref: IntentRef) => ref as unknown as Found;
/** Tokens as judged fit to hold: the credentials read from them, and when. */
interface Judged {
	readonly credentials: Credentials;
	readonly now: number;
}

/** A grant's intents through the browser, over its records. */
export function intentsWith(p: IntentsParts): GrantIntents {
	const { records, settings } = p;
	const secret = secretFrom(p.random);
	const connections = connectionsIn(settings, p.upstreams);
	const audited = declaredAudit(p.audit, events);
	const callbackUrl = (name: string) => `${p.origin}${browserBase}/callback/${name}`;
	const failure = ({ grant }: Found, outcome: string, from: Sourced) =>
		audited.record("federation.grant.authorization_failed", {
			subject: grant.subject,
			attributes: {
				client: grant.client,
				connection: grant.connection,
				outcome,
				...(from.source ? { source: from.source } : {}),
			},
		});

	/** The grant and its intent, while the intent is the grant's current one, not ended and within its time. */
	const liveIntent = async (step: Pick<Step, "grant" | "intent"> | undefined) => {
		if (!step) return undefined;
		const grant = records.grantOf(await p.grants.read(step.grant));
		const intent = grant?.intent;
		if (!grant || !intent || intent.id !== step.intent || intent.ended) return undefined;
		if (intent.endsAt <= p.clock.now() || grant.status === "revoked") return undefined;
		return { grant, intent };
	};
	/** Changes the intent only while it is still the grant's current one. */
	const changeIntent = ({ grant, intent }: Found, next: (intent: Intent) => Intent | undefined) =>
		p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (!now?.intent || now.intent.id !== intent.id || now.intent.ended) return undefined;
			const changed = next(now.intent);
			return changed && { value: records.stored({ ...now, intent: changed }) };
		});
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
	/** Takes a step once: answers it as it was, or none when it was taken already or does not match. */
	const take = async (secretText: string, kind: Step["kind"]) => {
		const changed = await p.steps.change(secretText, (stored) => {
			const step = records.stepOf(stored);
			if (!step || step.kind !== kind || step.taken) return undefined;
			return { value: records.storedStep({ ...step, taken: true }) };
		});
		const before = records.stepOf(changed?.before);
		const after = records.stepOf(changed?.after);
		return before && !before.taken && after?.taken ? before : undefined;
	};
	/** Back to the intent's return URI with the grant, the client's state and what came of it, if the client still lists it. */
	const back = async ({ grant, intent }: Found, error?: string): Promise<Back> => {
		if (!returnsTo(await p.clients.find(grant.client), intent.returnUri)) return { kind: "stale" };
		const to = new URL(intent.returnUri);
		to.searchParams.set("grant_id", grant.id);
		to.searchParams.set("state", intent.state);
		if (error) to.searchParams.set("error", error);
		return { kind: "back", location: to.href };
	};
	const failed: GrantIntents["failed"] = async (ref, error, from) => {
		const found = foundOf(ref);
		await changeIntent(found, (i) => ({ ...i, ended: error }));
		failure(found, from.outcome ?? error, from);
		return back(found, error);
	};

	return {
		connected: Object.keys(settings.connections).length > 0,
		connectUrl: (handle) => `${p.origin}${browserBase}/connect?request=${handle}`,
		callbackUrl,
		callbackOf: (path) => {
			const prefix = `${browserBase}/callback/`;
			const named = path.startsWith(prefix) ? path.slice(prefix.length) : undefined;
			return named !== undefined && connectionName.safeParse(named).success ? named : undefined;
		},
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
		resumed: async (taken) => {
			const kept = carried.safeParse(taken);
			const step = kept.success ? kept.data : undefined;
			const found = step ? await liveIntent(step) : undefined;
			if (!step || !found) return { kind: "stale" };
			const configured = connections.configured(found.grant.connection);
			if (!configured) return { kind: "unconfigured", ref: refOf(found) };
			const { grant, intent } = found;
			const { connection } = configured;
			return {
				kind: "resumed",
				ref: refOf(found),
				view: {
					subject: grant.subject,
					connection: grant.connection,
					idp: connection.idp,
					expected: {
						...(grant.upstream ? { held: grant.upstream } : {}),
						...(intent.expectedUpstream === undefined ? {} : { subject: intent.expectedUpstream }),
					},
					scopes: intent.scopes,
					...(connection.resource ? { resource: connection.resource } : {}),
					session: step.session,
				},
			};
		},
		stillValid: async (ref) => {
			const { grant, intent } = foundOf(ref);
			if (await p.judge.intentRevoked(grant, intent)) return "access_denied";
			if (intent.kind === "reauthorization" && (await p.judge.revoked(grant)))
				return "access_denied";
			return undefined;
		},
		judged: (ref, tokens) => {
			const { grant, intent } = foundOf(ref);
			const connection = connections.of(grant.connection);
			if (!connection) return { kind: "refused", why: "grant_not_authorizable" };
			const now = p.clock.now();
			const read = credentialsFrom(tokens, {
				now,
				maxAccessMs: connection["max-access-token-lifetime"] * 1000,
				shown: intent.scopes,
			});
			if (read.kind === "refused") return { kind: "refused", why: read.why };
			const judged: Judged = { credentials: read.credentials, now };
			return { kind: "held", tokens: Object.freeze(judged) as unknown as HeldTokens };
		},
		activated: async (ref, reached) => {
			const found = foundOf(ref);
			const { grant, intent } = found;
			// Judged at `now`, which the activation keeps.
			const { credentials, now } = reached.tokens as unknown as Judged;
			const { upstream } = reached;
			const changed = await p.grants.change(grant.id, (stored) => {
				const was = records.grantOf(stored);
				if (
					!was?.intent ||
					was.intent.id !== intent.id ||
					was.intent.ended ||
					was.intent.endsAt <= now ||
					was.status === "revoked"
				)
					return undefined;
				const { reason: _cleared, ...rest } = was;
				const next: Grant = {
					...rest,
					status: "active",
					scopes: intent.scopes,
					authorizedAt: now,
					expiresAt: now + intent.lifetimeMs,
					upstream: { issuer: upstream.issuer, subject: upstream.subject },
					intent: { ...intent, ended: "connected" },
					version: secret(),
					rotations: { from: now, count: 0 },
				};
				return {
					value: records.stored({ ...next, sealed: records.seal(next, credentials) }),
					lifetimeMs: intent.lifetimeMs + retentionMs,
				};
			});
			if (
				records.grantOf(changed?.after)?.intent?.ended !== "connected" ||
				records.grantOf(changed?.before)?.intent?.id !== intent.id
			) {
				return failed(ref, "grant_not_authorizable", reached);
			}
			audited.record(
				intent.kind === "initial" ? "federation.grant.authorized" : "federation.grant.reauthorized",
				{
					subject: grant.subject,
					attributes: {
						client: grant.client,
						connection: grant.connection,
						outcome: reached.identityCheck,
						...(reached.source ? { source: reached.source } : {}),
					},
				},
			);
			// The grant is active: what is left only tidies, and does not undo it.
			if (intent.kind === "initial") {
				try {
					await p.pending.remove(`${grant.client}\n${grant.subject}`, grant.id);
				} catch (error) {
					const kind = error instanceof Error ? error.name : typeof error;
					p.log.warn("federation-grants.pending_remove_failed", { kind });
				}
			}
			await p.listed(grant, intent.lifetimeMs + retentionMs);
			return back(found);
		},
		failed,
		noted: (ref, outcome, from) => failure(foundOf(ref), outcome, from),
		unanswered: (from) =>
			audited.record("federation.grant.authorization_failed", {
				attributes: { outcome: "unavailable", ...(from.source ? { source: from.source } : {}) },
			}),
	};
}

export const intentsTakes = [
	clients,
	upstreams,
	grantStore,
	stepStore,
	pendingIntents,
	audit,
] as const;

/** The intents over the contracts the assembly gives. */
export const intentsOver = async (c: BuildContext<Settings>) =>
	intentsWith({
		...(await c.get(shared)),
		clients: await c.get(clients),
		upstreams: await c.get(upstreams),
		grants: await c.get(grantStore),
		steps: await c.get(stepStore),
		pending: await c.get(pendingIntents),
		audit: await c.get(audit),
		settings: c.section,
		clock: c.clock,
		random: c.random,
		log: c.log,
	});
