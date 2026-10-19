import { createHash } from "node:crypto";
import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Clients, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import {
	type BuildContext,
	type Clock,
	contract,
	isUnavailable,
	type Log,
	type Random,
} from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { type Sessions, sessions } from "@mod/session";
import {
	type DelegatedExchange,
	type Delegation,
	type DelegationStart,
	UpstreamRefused,
	type Upstreams,
	upstreams,
} from "@mod/upstreams";
import { type Users, users } from "@mod/users";
import events from "../audit-events.ts";
import {
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

export interface ConnectParts {
	readonly sessions: Sessions;
	readonly clients: Clients;
	readonly users: Users;
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

export const browserBase = "/session/federation-grants";

const plain = (status: number, text: string): HttpResponse => ({
	status,
	headers: {
		...noStore,
		"content-type": "text/plain; charset=utf-8",
		"referrer-policy": "no-referrer",
	},
	body: text,
});
const json = (status: number, body: unknown): HttpResponse =>
	jsonAnswer(status, body, { headers: { "referrer-policy": "no-referrer" } });
const see = (location: string): HttpResponse => ({
	status: 303,
	headers: { ...noStore, location, "referrer-policy": "no-referrer" },
});
const stale = () => plain(400, "This request has expired or has already been used. Start again.");
const invalid = () =>
	json(400, { error: "invalid_request", error_description: "the request is not valid" });

/** A start as the upstream takes it: where to send the browser, refused as a value, or not askable now. */
const startOf = (delegation: Delegation | undefined, start: DelegationStart) => {
	try {
		const built = delegation?.authorizationUrl(start);
		if (built === undefined) return { kind: "unavailable" } as const;
		return typeof built === "string"
			? ({ kind: "url", location: built } as const)
			: ({ kind: "refused" } as const);
	} catch {
		// A start the type throws at cannot be asked now; never a 500.
		return { kind: "unavailable" } as const;
	}
};

/** The upstream's login for a code, or the error the browser is sent back with. */
const exchangedBy = async (delegation: Delegation, exchange: DelegatedExchange) => {
	try {
		return { kind: "login", login: await delegation.exchange(exchange) } as const;
	} catch (error) {
		if (isUnavailable(error)) return { kind: "failed", error: "temporarily_unavailable" } as const;
		if (error instanceof UpstreamRefused)
			return { kind: "failed", error: "upstream_error" } as const;
		throw error;
	}
};

/** The browser half: the link a client sends the user to, the question, the user's decision, and the upstream's callback. */
export function connectWith(p: ConnectParts) {
	const { records, settings } = p;
	const secret = secretFrom(p.random);
	const connections = connectionsIn(settings, p.upstreams);
	const callbackOf = (name: string) => `${p.origin}${browserBase}/callback/${name}`;
	const audited = declaredAudit(p.audit, events);
	/** Audits a connection that failed, by its outcome. */
	const auditFailure = (grant: Grant, outcome: string, request: HttpRequest) => {
		const from = determinedSource(request);
		audited.record("federation.grant.authorization_failed", {
			subject: grant.subject,
			attributes: {
				client: grant.client,
				connection: grant.connection,
				outcome,
				...(from ? { source: from } : {}),
			},
		});
	};

	/** The grant and its intent, while the intent is the grant's current one, not ended and within its time. */
	const liveIntent = async (step: Step | undefined) => {
		if (!step) return undefined;
		const grant = records.grantOf(await p.grants.read(step.grant));
		const intent = grant?.intent;
		if (!grant || !intent || intent.id !== step.intent || intent.ended) return undefined;
		if (intent.endsAt <= p.clock.now() || grant.status === "revoked") return undefined;
		return { grant, intent };
	};
	/** Changes the intent only while it is still the grant's current one. */
	const changeIntent = (
		grant: Grant,
		intent: Intent,
		next: (intent: Intent) => Intent | undefined,
	) =>
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
	/** Marks the intent's trip to raise the session for `requirement`; true only for the request that marked it. */
	const stepUpOnce = async (
		grant: Grant,
		intent: Intent,
		requirement: string,
		authenticatedAt: number,
	) => {
		if (!mayStep(intent.stepped, requirement, authenticatedAt)) return false;
		const trip = { requirement, at: p.clock.now() };
		const marked = await changeIntent(grant, intent, (i) =>
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
	};
	/** Takes a step once: answers it as it was, or none when it was taken already or does not match. */
	const take = async (
		secretText: string,
		kind: Step["kind"],
		matches: (step: Step) => boolean = () => true,
	) => {
		const changed = await p.steps.change(secretText, (stored) => {
			const step = records.stepOf(stored);
			if (!step || step.kind !== kind || step.taken || !matches(step)) return undefined;
			return { value: records.storedStep({ ...step, taken: true }) };
		});
		const before = records.stepOf(changed?.before);
		const after = records.stepOf(changed?.after);
		return before && !before.taken && after?.taken ? before : undefined;
	};
	/** The session at use level, as the intent's subject; a short one is told whose it is first. */
	const entered = async (request: HttpRequest, grant: Grant) => {
		const other = { kind: "other" } as const;
		const entry = await p.sessions.enterFor(request, "use");
		if (entry.kind === "entered")
			return entry.session.context.subject === grant.subject ? entry : other;
		if (entry.kind !== "short") return entry;
		// A short entry names no subject: the level that grants nothing tells whose session it is.
		const bare = await p.sessions.enterFor(request, "none");
		if (bare.kind !== "entered") return { kind: "unknown" } as const;
		const { context } = bare.session;
		return context.subject === grant.subject ? { ...entry, context } : other;
	};

	const connect = async (request: HttpRequest): Promise<HttpResponse> => {
		const handle = request.query.single("request");
		const step = handle ? records.stepOf(await p.steps.read(handle)) : undefined;
		const found = step?.kind === "link" ? await liveIntent(step) : undefined;
		if (!handle || !found) return stale();
		const { grant, intent } = found;
		const self = `${p.origin}${browserBase}/connect?request=${handle}`;
		const entry = await entered(request, grant);
		if (entry.kind === "absent") {
			const page = settings["login-page"];
			if (!page) return plain(401, "Sign in, then open this link again.");
			const login = new URL(page);
			login.searchParams.set("redirect_to", self);
			return see(login.href);
		}
		if (entry.kind === "other") return plain(403, "This request was made for another account.");
		if (entry.kind === "unknown") {
			auditFailure(grant, "reauthentication_required", request);
			return plain(403, "Sign in again to continue.");
		}
		// Told only to the subject's own session, so a link's holder learns nothing of the client.
		const client = await p.clients.find(grant.client);
		if (!permits(client, grant.connection) || !connections.of(grant.connection)) {
			return plain(403, "This connection is not available.");
		}
		if (entry.kind === "short") {
			const page = settings["step-up-page"];
			const { requirement, context } = entry;
			if (!page || !(await stepUpOnce(grant, intent, requirement, context.authenticatedAt))) {
				auditFailure(grant, "reauthentication_required", request);
				return plain(403, "Sign in again to continue.");
			}
			const raise = new URL(page);
			raise.searchParams.set("requirement", requirement);
			raise.searchParams.set("redirect_to", self);
			return see(raise.href);
		}
		// The first browser to take a question holds the intent; another is told to start again.
		const session = entry.session.id;
		if (intent.session !== undefined && intent.session !== session) return stale();
		const bound = await changeIntent(grant, intent, (i) =>
			i.session === undefined ? { ...i, session } : i.session === session ? i : undefined,
		);
		if (records.grantOf(bound?.after)?.intent?.session !== session) return stale();
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
		// Boot refuses connections without a page, and a grant whose connection is gone returned above.
		const page = new URL(settings.page ?? "");
		page.searchParams.set("challenge", challenge);
		return see(page.href);
	};

	/** A question still open, asked of this browser's session for the intent's subject. */
	const asked = async (request: HttpRequest, step: Step | undefined) => {
		const found = step?.kind === "question" && !step.taken ? await liveIntent(step) : undefined;
		if (!step || !found) return { kind: "refused", answer: invalid() } as const;
		const entry = await entered(request, found.grant);
		if (entry.kind === "absent") {
			return {
				kind: "refused",
				answer: json(401, {
					error: "login_required",
					error_description: "no authenticated session",
				}),
			} as const;
		}
		if (entry.kind !== "entered" || entry.session.id !== step.session) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "reauthentication_required",
					error_description: "sign in again to continue",
				}),
			} as const;
		}
		if (!permits(await p.clients.find(found.grant.client), found.grant.connection)) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "access_denied",
					error_description: "connection_not_permitted",
				}),
			} as const;
		}
		return { kind: "asked", ...found } as const;
	};

	const question = async (request: HttpRequest): Promise<HttpResponse> => {
		const challenge = request.query.single("challenge");
		if (!challenge)
			return json(400, { error: "invalid_request", error_description: "challenge is required" });
		const read = await asked(request, records.stepOf(await p.steps.read(challenge)));
		if (read.kind === "refused") return read.answer;
		const { grant, intent } = read;
		const resource = connections.of(grant.connection)?.resource;
		return json(200, {
			challenge,
			client_id: grant.client,
			connection: grant.connection,
			scopes: intent.scopes,
			...(resource ? { resource } : {}),
			grant_expires_in: intent.lifetimeMs / 1000,
			continues_after_logout: true,
			expires_in: Math.max(0, Math.floor((intent.endsAt - p.clock.now()) / 1000)),
		});
	};

	/** Sends the browser back to the intent's return URI, with the grant, the client's state and what came of it. */
	const back = (intent: Intent, grant: Grant, error?: string) => {
		const to = new URL(intent.returnUri);
		to.searchParams.set("grant_id", grant.id);
		to.searchParams.set("state", intent.state);
		if (error) to.searchParams.set("error", error);
		return see(to.href);
	};
	/** Ends the intent with why, audits it, and sends the browser back with the error, if the client still lists the return. */
	const fail = async (
		request: HttpRequest,
		grant: Grant,
		intent: Intent,
		error: string,
		outcome = error,
	) => {
		await changeIntent(grant, intent, (i) => ({ ...i, ended: error }));
		auditFailure(grant, outcome, request);
		if (!returnsTo(await p.clients.find(grant.client), intent.returnUri)) return stale();
		return back(intent, grant, error);
	};

	const decide = async (request: HttpRequest): Promise<HttpResponse> => {
		const challenge = request.form.single("challenge");
		const decision = request.form.single("decision");
		if (!challenge)
			return json(400, { error: "invalid_request", error_description: "challenge is required" });
		if (decision !== "accept" && decision !== "deny") return invalid();
		const read = await asked(request, records.stepOf(await p.steps.read(challenge)));
		if (read.kind === "refused") return read.answer;
		const { grant, intent } = read;
		if (decision === "deny") {
			if (!(await take(challenge, "question"))) return invalid();
			return fail(request, grant, intent, "access_denied");
		}
		const resource = connections.of(grant.connection)?.resource;
		const state = secret();
		const verifier = secret();
		const nonce = secret();
		// Built before the question is spent, so a start that cannot be asked now leaves it open.
		const started = startOf(connections.configured(grant.connection)?.delegation, {
			state,
			nonce,
			challenge: createHash("sha256").update(verifier).digest("base64url"),
			challengeMethod: "S256",
			redirectUri: callbackOf(grant.connection),
			scopes: intent.scopes,
			...(resource ? { resource } : {}),
		});
		if (started.kind === "unavailable") {
			auditFailure(grant, "upstream_unavailable", request);
			return json(503, {
				error: "temporarily_unavailable",
				error_description: "upstream_unavailable",
			});
		}
		if (!(await take(challenge, "question"))) return invalid();
		if (started.kind === "refused") {
			// The upstream will not start this delegation: the intent ends, and the client is told.
			return fail(request, grant, intent, "grant_not_authorizable", "upstream_refused_start");
		}
		const upstream = {
			format: 1,
			kind: "upstream",
			grant: grant.id,
			intent: intent.id,
			session: intent.session ?? "",
			verifier,
			nonce,
			connection: grant.connection,
		} as const;
		await p.steps.create(
			state,
			records.storedStep(upstream),
			Math.max(1, intent.endsAt - p.clock.now()),
		);
		return see(started.location);
	};

	/** The checks a callback runs before it activates, each answering the error the browser is sent back with. */
	const verified = async (request: HttpRequest, grant: Grant, intent: Intent, step: Step) => {
		const entry = await entered(request, grant);
		if (entry.kind !== "entered" || entry.session.id !== step.session)
			return "reauthentication_required";
		if (await p.judge.intentRevoked(grant, intent)) return "access_denied";
		if (intent.kind === "reauthorization" && (await p.judge.revoked(grant))) return "access_denied";
		return undefined;
	};

	const callback = async (request: HttpRequest, name: string): Promise<HttpResponse> => {
		const state = request.query.single("state");
		// Taken before any code is used, and only at the connection it was made for.
		const step = state ? await take(state, "upstream", (s) => s.connection === name) : undefined;
		const found = step ? await liveIntent(step) : undefined;
		if (!step || !found) return stale();
		const { grant, intent } = found;
		const configured = connections.configured(name);
		if (!configured) return fail(request, grant, intent, "grant_not_authorizable");
		const { connection, delegation } = configured;
		const refused = await verified(request, grant, intent, step);
		if (refused) return fail(request, grant, intent, refused);
		const code = request.query.single("code");
		if (request.query.repeated().length > 0 || request.query.has("error") || !code) {
			return fail(
				request,
				grant,
				intent,
				request.query.has("error") ? "access_denied" : "upstream_error",
			);
		}
		const exchanged = await exchangedBy(delegation, {
			code,
			verifier: step.verifier ?? "",
			redirectUri: callbackOf(name),
			nonce: step.nonce ?? "",
			iss: request.query.single("iss"),
			scopes: intent.scopes,
			...(connection.resource ? { resource: connection.resource } : {}),
		});
		if (exchanged.kind === "failed") return fail(request, grant, intent, exchanged.error);
		const { login } = exchanged;
		const upstream = { issuer: String(login.issuer), subject: String(login.subject) };
		const known = grant.upstream;
		if (known && (known.issuer !== upstream.issuer || known.subject !== upstream.subject)) {
			return fail(request, grant, intent, "account_mismatch");
		}
		if (intent.expectedUpstream !== undefined && intent.expectedUpstream !== upstream.subject) {
			return fail(request, grant, intent, "account_mismatch");
		}
		if (settings["identity-check"] === "required") {
			const holder = await p.users.byUpstream(connection.idp, upstream.subject).then(
				(found) => (found.kind === "none" ? "nobody" : found.user.subject),
				() => undefined,
			);
			if (holder === undefined) return fail(request, grant, intent, "identity_unverifiable");
			if (holder !== "nobody" && holder !== grant.subject)
				return fail(request, grant, intent, "identity_conflict");
		}
		const now = p.clock.now();
		const read = credentialsFrom(login.tokens, {
			now,
			maxAccessMs: connection["max-access-token-lifetime"] * 1000,
			shown: intent.scopes,
		});
		if (read.kind === "refused") return fail(request, grant, intent, read.why);
		// Checked again just before the activation: the upstream leg may have taken long.
		const again = await verified(request, grant, intent, step);
		if (again) return fail(request, grant, intent, again);
		const changed = await p.grants.change(grant.id, (stored) => {
			const was = records.grantOf(stored);
			if (
				!was?.intent ||
				was.intent.id !== intent.id ||
				was.intent.ended ||
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
				upstream,
				intent: { ...intent, ended: "connected" },
				version: secret(),
				rotations: { from: now, count: 0 },
			};
			return {
				value: records.stored({ ...next, sealed: records.seal(next, read.credentials) }),
				lifetimeMs: intent.lifetimeMs + retentionMs,
			};
		});
		if (
			records.grantOf(changed?.after)?.intent?.ended !== "connected" ||
			records.grantOf(changed?.before)?.intent?.id !== intent.id
		) {
			return fail(request, grant, intent, "grant_not_authorizable");
		}
		if (intent.kind === "initial")
			await p.pending.remove(`${grant.client}\n${grant.subject}`, grant.id);
		await p.listed(grant, intent.lifetimeMs + retentionMs);
		const from = determinedSource(request);
		const kind =
			intent.kind === "initial" ? "federation.grant.authorized" : "federation.grant.reauthorized";
		audited.record(kind, {
			subject: grant.subject,
			attributes: {
				client: grant.client,
				connection: grant.connection,
				outcome: settings["identity-check"],
				...(from ? { source: from } : {}),
			},
		});
		if (!returnsTo(await p.clients.find(grant.client), intent.returnUri)) return stale();
		return back(intent, grant);
	};

	/** Answers the browser half's routes; anything unavailable is a plain 503. */
	const guarded =
		(handle: (request: HttpRequest) => Promise<HttpResponse>) =>
		async (request: HttpRequest): Promise<HttpResponse> => {
			try {
				return await handle(request);
			} catch (error) {
				if (!isUnavailable(error)) throw error;
				p.log.error("federation-grants.browser_unavailable", { path: request.path.slice(0, 100) });
				return plain(503, "This service is unavailable. Try again later.");
			}
		};
	return {
		connect: guarded(connect),
		question: guarded(question),
		decide: guarded(decide),
		callback: guarded(async (request) => {
			const name = request.path.slice(`${browserBase}/callback/`.length);
			if (!connectionName.safeParse(name).success) return plain(404, "Not found.");
			return callback(request, name);
		}),
	};
}

/** The browser half, built once for its routes. */
export const browser = contract<ReturnType<typeof connectWith>>("federation-grants.browser");

/** The browser half over the contracts the assembly gives. */
export const connectOver = async (c: BuildContext<Settings>) =>
	connectWith({
		...(await c.get(shared)),
		sessions: await c.get(sessions),
		clients: await c.get(clients),
		users: await c.get(users),
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
