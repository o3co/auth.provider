import { audit } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import type { Clients } from "@mod/clients";
import type { HttpResponse } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import { type EntryRequirement, entryRequirements, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import type {
	DelegatedExchange,
	Delegation,
	DelegationStart,
	Upstreams,
	UpstreamTokens,
} from "@mod/upstreams";
import type { Users } from "@mod/users";
import { memoryStores } from "../../../test/stores.ts";
import {
	type Grant,
	type Intent,
	judgeWith,
	listingWith,
	recordsWith,
	retentionMs,
} from "../../grant/grant.ts";
import { section } from "../../section.ts";
import { browserBase, connectWith } from "../connect.ts";

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

/** The login an upstream answers a code with, for `u-alice` unless said. */
export const upstreamLogin = (tokens: unknown = upstreamTokens(), subject = "u-alice") => ({
	subject,
	amr: [],
	issuer: "https://up.example",
	tokens,
});

/** A requirement a session falls short of to be used, and at every level while `every` is set. */
export const shortToUse = (short = { every: false }): EntryRequirement => ({
	name: "mfa",
	judges: ["use", "credentials"],
	admits: async (_context, level) =>
		level === "use" || short.every
			? { kind: "short", answer: { error: "mfa_required" } }
			: { kind: "admit" },
});

export type Answer = {
	status: number;
	headers: Record<string, string>;
	json?: Record<string, unknown> | undefined;
	text?: string;
};
const read = (response: HttpResponse): Answer => {
	const body = response.body as { json?: Record<string, unknown> } | string | undefined;
	return {
		status: response.status,
		headers: { ...response.headers },
		...(typeof body === "string" ? { text: body } : { json: body?.json }),
	};
};

/**
 * The browser half alone, over memory stores, the session and revocation stand-ins, a test
 * upstream `corp` behind the connection `cal`, and a client `worker` that may use it. Intents are
 * written as a lodging writes them.
 */
export async function connector(
	options: {
		readonly settings?: Readonly<Record<string, unknown>>;
		readonly requirements?: readonly EntryRequirement[];
		/** Who holds which upstream account, or `down` when the users cannot say. */
		readonly holders?: Readonly<Record<string, string>>;
		readonly resource?: string;
		/** Another harness's stores, as after a restart with other settings. */
		readonly stores?: ReturnType<typeof memoryStores>;
	} = {},
) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const stores = options.stores ?? memoryStores(() => now, 3);
	const recorded = auditStandIn();
	const script = {
		exchange: async (_x: DelegatedExchange): Promise<unknown> => upstreamLogin(),
		startThrows: false,
		withdrawn: false,
	};
	const asked = { starts: [] as DelegationStart[] };
	const delegation = {
		authorizationUrl: (start) => {
			if (script.startThrows) throw new Error("cannot build");
			asked.starts.push(start);
			return `https://up.example/authorize?state=${start.state}`;
		},
		exchange: (x) => script.exchange(x) as ReturnType<Delegation["exchange"]>,
	} as Delegation;
	const upstreams: Upstreams = {
		of: (idp) => (idp === "corp" && !script.withdrawn ? { delegation } : undefined),
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
	const holders = options.holders ?? {};
	const users = {
		byUpstream: async (_idp: string, subject: string) => {
			const holder = holders[subject];
			if (holder === "down") throw new Unavailable("ledger");
			return holder === undefined
				? { kind: "none" }
				: { kind: "user", user: { subject: holder, attributes: {} } };
		},
	} as unknown as Users;
	const requirements = defineModule({ name: "requirements" }, (m) =>
		(options.requirements ?? []).map((r) => m.contribute(entryRequirements).by(() => r)),
	);
	const app = await assemble({
		modules: [http, sessionStandIn, subjectRevocationStandIn, recorded.module, requirements],
		config: { ...kernelConfig(), ...httpConfig({ "public-origin": origin }) },
		runtime,
	});
	const settings = section.parse({
		page: `${origin}/consent-page`,
		connections: {
			cal: { idp: "corp", scopes, "max-access-token-lifetime": "1h", resource: options.resource },
		},
		...options.settings,
	});
	const records = recordsWith(seal);
	const browser = connectWith({
		sessions: app.get(sessions),
		clients,
		users,
		upstreams,
		grants: stores.grants,
		steps: stores.steps,
		pending: stores.pending,
		records,
		judge: judgeWith(app.get(revocations), {
			keep: settings["keep-on-subject-revocation"],
			maxMs: settings["max-lifetime"] * 1000,
			allowanceMs: settings["revocation-skew"] * 1000,
		}),
		listed: listingWith(stores.subjects, logged.log),
		audit: app.get(audit),
		settings,
		origin,
		...runtime,
	});

	let n = 0;
	/** A pending grant of `alice` for `worker` at `cal`, with its intent and its link, as a lodging writes them. */
	const lodge = async (more: Partial<Intent> = {}) => {
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
		};
		const connectMs = settings["connect-lifetime"] * 1000;
		await stores.grants.create(grant.id, records.stored(grant), connectMs + retentionMs);
		const link = `link-${grant.id}`;
		const step = { format: 1, kind: "link", grant: grant.id, intent: intent.id } as const;
		await stores.steps.create(link, records.storedStep(step), connectMs);
		return { id: grant.id, link };
	};

	/** A browser's cookie for a new session of `subject`. */
	const login = async (subject = "alice") => {
		const done = await app
			.get(sessions)
			.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() });
		return (done.cookies[0] ?? "").split(";")[0] ?? "";
	};
	/** A browser's request to one of the steps, with its cookie and its query or form. */
	const step = async (
		name: "connect" | "question" | "decide" | "callback",
		cookie: string,
		params: Record<string, string | readonly string[]> = {},
		path = `${browserBase}/callback/cal`,
	) => {
		const values = new Map(
			Object.entries(params).map(([k, v]) => [k, typeof v === "string" ? [v] : [...v]]),
		);
		const request = testRequest({
			method: name === "decide" ? "POST" : "GET",
			path,
			headers: new Map([["cookie", cookie]]),
			...(name === "decide" ? { form: values } : { query: values }),
		});
		return read(await browser[name](request));
	};
	const location = (answer: Answer) => new URL(answer.headers.location ?? "", origin);

	/** Opens a link in a browser: the answer, and the challenge it carries. */
	const open = async (link: string, cookie: string) => {
		const opened = await step("connect", cookie, { request: link });
		return { opened, challenge: location(opened).searchParams.get("challenge") ?? "" };
	};
	/** Decides a challenge in a browser: the answer, and the upstream state it carries. */
	const decide = async (challenge: string, cookie: string, decision = "accept") => {
		const answered = await step("decide", cookie, { challenge, decision });
		return { answered, state: location(answered).searchParams.get("state") ?? "" };
	};
	/** Lodges an intent, and walks a browser of `alice` through the link and the question to the upstream. */
	const started = async (more: Partial<Intent> = {}) => {
		const { id, link } = await lodge(more);
		const browser = await login();
		const { opened, challenge } = await open(link, browser);
		const { answered, state } = await decide(challenge, browser);
		return { id, link, browser, opened, challenge, answered, state };
	};
	/** The upstream's return to the callback, as the browser brings it. */
	const callback = (
		state: string,
		browser: string,
		query: Record<string, readonly string[]> = {},
	) => step("callback", browser, { state: [state], code: ["code-1"], ...query });

	return {
		app,
		stores,
		script,
		asked,
		events: recorded.events,
		relist: (connections: string[], returns: string[]) => {
			listed.connections = connections;
			listed.returns = returns;
		},
		lodge,
		login,
		step,
		location,
		open,
		decide,
		started,
		callback,
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
