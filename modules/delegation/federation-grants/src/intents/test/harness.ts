import { audit } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import type { Clients } from "@mod/clients";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import type { Delegation, Upstreams, UpstreamTokens } from "@mod/upstreams";
import { memoryStores } from "../../../test/stores.ts";
import type { IntentRef } from "../../browser.ts";
import {
	type Grant,
	type Intent,
	judgeWith,
	listingWith,
	recordsWith,
	retentionMs,
} from "../../grant/grant.ts";
import { section } from "../../section.ts";
import { intentsWith } from "../intents.ts";

export const origin = "https://issuer.example";
export const back = "https://worker.example/connected";
export const scopes = ["openid", "offline_access", "read"];

/** A seal that opens only under the context it sealed for. */
const seal: Seal = {
	seal: (plain, context) => JSON.stringify([context, plain]),
	open: (sealed, context) => {
		const [bound, plain] = JSON.parse(sealed) as [string, string];
		return bound === context ? { kind: "opened", plain } : { kind: "refused" };
	},
};

/** Tokens an upstream gives, bearer with a refresh token and five minutes, unless said. */
export const upstreamTokens = (more: Readonly<Record<string, unknown>> = {}) =>
	({
		accessToken: "up-1",
		tokenType: "Bearer",
		refreshToken: "up-refresh-1",
		expiresInSeconds: 300,
		scope: scopes,
		...more,
	}) as unknown as UpstreamTokens;

/**
 * The intents alone, over memory stores and the revocation stand-in, a test upstream `corp` behind
 * the connection `cal`, and a client `worker` that may use it. Intents are written as a lodging writes them.
 */
export async function intents(options: { readonly settings?: Record<string, unknown> } = {}) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const stores = memoryStores(() => now, 3);
	const recorded = auditStandIn();
	const delegation = {
		authorizationUrl: () => "https://up.example/authorize",
		exchange: async () => {
			throw new Error("not exchanged here");
		},
	} as unknown as Delegation;
	const withdrawn = { idp: false };
	const upstreams: Upstreams = {
		of: (idp) => (idp === "corp" && !withdrawn.idp ? { delegation } : undefined),
	};
	const listed = { connections: ["cal"], returns: [back] };
	const clients = {
		find: async (id: string) =>
			id === "worker"
				? {
						id,
						registered: true,
						kind: "confidential",
						section: () => ({ connections: listed.connections, "return-uris": listed.returns }),
					}
				: undefined,
	} as unknown as Clients;
	const app = await assemble({
		modules: [subjectRevocationStandIn, recorded.module],
		config: kernelConfig(),
		runtime,
	});
	const settings = section.parse({
		page: `${origin}/consent-page`,
		connections: { cal: { idp: "corp", scopes, "max-access-token-lifetime": "1h" } },
		...options.settings,
	});
	const records = recordsWith(seal);
	const subject = intentsWith({
		clients,
		upstreams,
		grants: stores.grants,
		steps: stores.steps,
		pending: stores.pending,
		records,
		judge: judgeWith(app.get(revocations), {
			keep: settings["keep-on-subject-revocation"],
			maxMs: settings["max-lifetime"] * 1000,
		}),
		listed: listingWith(stores.subjects, logged.log),
		audit: app.get(audit),
		settings,
		origin,
		...runtime,
	});

	let n = 0;
	/** A pending grant of `alice` for `worker` at `cal`, with its intent and its link, as a lodging writes them. */
	const lodge = async (more: Partial<Intent> = {}, grantMore: Partial<Grant> = {}) => {
		n++;
		const intent: Intent = {
			id: `intent-${n}`,
			kind: "initial",
			returnUri: back,
			state: "st",
			scopes,
			lifetimeMs: settings["default-lifetime"] * 1000,
			startedAt: now,
			endsAt: now + settings["connect-lifetime"] * 1000,
			...more,
		};
		const grant: Grant = {
			format: 1,
			id: `grant-${n}`,
			client: "worker",
			subject: "alice",
			connection: "cal",
			status: "pending",
			createdAt: now,
			scopes: intent.scopes,
			intent,
			version: `v-${n}`,
			rotations: { from: now, count: 0 },
			...grantMore,
		};
		const connectMs = settings["connect-lifetime"] * 1000;
		await stores.grants.create(grant.id, records.stored(grant), connectMs + retentionMs);
		const link = `link-${grant.id}`;
		const step = { format: 1, kind: "link", grant: grant.id, intent: intent.id } as const;
		await stores.steps.create(link, records.storedStep(step), connectMs);
		return { id: grant.id, link };
	};
	/** A lodged intent's ref, read through its link. */
	const linked = async (link: string) => {
		const found = await subject.linked(link);
		if (found.kind !== "linked") throw new Error("not linked");
		return found;
	};
	/** A lodged intent, bound to `session`, with its question. */
	const questioned = async (session = "s-1", more: Partial<Intent> = {}) => {
		const { id, link } = await lodge(more);
		const { ref } = await linked(link);
		const bound = await subject.bound(ref, session);
		if (bound.kind !== "bound") throw new Error("not bound");
		return { id, link, ref, challenge: bound.challenge };
	};
	/** The grant as kept. */
	const grantOf = (id: string) => records.grantOf(stores.peek(id) as never);

	return {
		intents: subject,
		stores,
		events: recorded.events,
		logs: () => logged.lines(),
		revoke: (who = "alice") => app.get(revocations).record(who),
		relist: (connections: string[], returns: string[]) => {
			listed.connections = connections;
			listed.returns = returns;
		},
		withdraw: () => {
			withdrawn.idp = true;
		},
		lodge,
		linked,
		questioned,
		grantOf,
		/** The tokens as judged fit to hold for `ref`. */
		held: (ref: IntentRef, tokens: unknown) => {
			const judged = subject.judged(ref, tokens);
			if (judged.kind !== "held") throw new Error(judged.why);
			return judged.tokens;
		},
		/** Before the next write of a grant, another writer changes it, and its intent, as given. */
		meanwhile: (more: object, intent: object = {}) =>
			stores.raceNext((record) => {
				const r = record as unknown as { intent: object };
				return { ...r, ...more, intent: { ...r.intent, ...intent } } as never;
			}),
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
}
