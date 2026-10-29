import { auditStandIn } from "@mod/audit/testing";
import { clientSources } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type HttpResponse, listening, type Route, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { issuer } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import secretHashModule from "@mod/secret-hash/module";
import { senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { type Session, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { sessionTokens } from "@mod/session-tokens";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { accessConditions, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import {
	type Upstream,
	type UpstreamLoginReceiver,
	type UpstreamTokens,
	upstreamLoginReceivers,
	upstreams,
} from "@mod/upstreams";
import federationTokens from "../src/module.ts";
import { type FederationTokensSettings, federationTokensConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

/** What the test's upstream offers beyond the login: a refresh and an end of session. */
export type Offered = Pick<Upstream, "refresh" | "endSession">;

const probed = contract<{
	readonly route: Route;
	readonly receivers: readonly UpstreamLoginReceiver[];
	readonly all: readonly Route[];
}>("test.probed");

/** The client the scenes call with: a receiver, with one return after an upstream logout. */
export const receiver = "app";
export const back = "https://app.example/after";
/** A client a source names rather than the operator, whose metadata says it receives. */
export const named = "https://named.example/app";
/** A client whose source cannot be read. */
export const unreadable = "https://unreadable.example/app";
/** The key a DPoP-bound token is bound to, which every request presenting one proves. */
const dpop = { member: "jkt", confirmation: "key-1", tokenType: "DPoP" } as const;

/**
 * federation-tokens composed with stand-ins: tokens, sessions and clients that are real enough,
 * a session index and a family lineage the test sets, and an upstream named `corp` (and `other`).
 */
export async function harness(
	options: {
		readonly settings?: Partial<FederationTokensSettings>;
		readonly offered?: Offered;
		/** The seal section in place of the test's one key: a ring with past keys, say. */
		readonly seal?: Readonly<Record<string, unknown>>;
	} = {},
) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const bound = new Map<string, string>();
	const families = new Map<string, "family" | "ended">();
	const stores = memoryStores(() => now);
	const recorded = auditStandIn();
	const offered: Record<string, Offered> = { corp: options.offered ?? {}, other: {} };
	/** Subjects whose sessions fall short of a requirement at use. */
	const short = new Set<string>();
	const stubs = defineModule(
		{ name: "stubs", replicaSafe: false, takes: [routes, upstreamLoginReceivers] },
		(m) => [
			m.provide(issuer).by(() => ({ url: "https://issuer.example" })),
			m.provide(sessionTokens).by(() => ({
				sessionOf: async (id) => {
					const handle = bound.get(id);
					return handle === undefined ? { kind: "unbound" } : { kind: "bound", handle };
				},
			})),
			// As refresh's condition: a token whose family ended is revoked, in every check of it.
			m.contribute(accessConditions).by(() => ({
				name: "refresh",
				holds: async ({ id }) => (families.get(id) === "ended" ? "revoked" : "holds"),
			})),
			m.provide(upstreams).by(() => ({ of: (idp) => offered[idp] })),
			m.contribute(entryRequirements).by(() => ({
				name: "test-short",
				judges: ["use"],
				admits: async (context) =>
					short.has(context.subject)
						? { kind: "short", answer: { error: "test_short" } }
						: { kind: "admit" },
			})),
			m.contribute(clientSources).by(() => ({
				find: async (id) => {
					if (id === unreadable) throw new Unavailable("clients");
					if (id !== named) return undefined;
					const sections = { "federation-tokens": { receives: true } };
					return { id, kind: "public", method: "none", sections };
				},
			})),
			m.contribute(senderBindings).by(() => ({
				member: dpop.member,
				tokenType: dpop.tokenType,
				read: async () => ({ kind: "bound", confirmation: dpop.confirmation }),
			})),
			m.provide(probed).by(async (c) => ({
				route: (await c.collect(routes)).find((r) => r.path === "/oauth/federation/*") as Route,
				receivers: await c.collect(upstreamLoginReceivers),
				all: await c.collect(routes),
			})),
		],
	);
	const input = {
		modules: [
			http,
			clientsModule,
			secretHashModule,
			senderBindingModule,
			tokensStandIn(),
			sessionStandIn,
			sessionRequirements,
			sessionParticipants,
			subjectRevocationStandIn,
			rateLimitStandIn,
			recorded.module,
			sealModule,
			stores.module,
			stubs,
			federationTokens,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...(options.seal ? { seal: options.seal } : sealConfig()),
			...clientsConfig([
				confidentialClient({
					id: receiver,
					sections: {
						"federation-tokens": { receives: true, "post-logout-redirect-uris": [back] },
					},
				}),
				confidentialClient({ id: "plain" }),
			]),
			...federationTokensConfig(options.settings),
		},
		runtime,
	};
	const app = await assemble(input);
	const { route, receivers, all } = app.get(probed);
	/** A session opened for `subject`. */
	const login = async (subject = "alice") => {
		const facts = { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() };
		return (await app.get(sessions).complete(testRequest(), facts)).session;
	};
	/** An access token issued to `client` in the session, whose audience names the client and whose subject is the session's. */
	const issue = async (
		session: Session,
		client = receiver,
		more: {
			readonly audience?: readonly string[];
			readonly family?: "family" | "ended";
			readonly subject?: string;
			readonly dpop?: boolean;
		} = {},
	) => {
		const given = await app.get(tokens).issue(
			{
				grant: {
					subject: more.subject ?? session.context.subject,
					issuedTo: client,
					audience: more.audience ?? [client],
					scope: [],
				},
				grantType: "session",
				session: session.id,
			},
			more.dpop ? { binding: dpop } : {},
		);
		if (given.kind === "refused") throw new Error(given.description);
		const issued = given.access;
		bound.set(issued.id, session.id);
		families.set(issued.id, more.family ?? "family");
		return { token: issued.token, id: issued.id };
	};
	/** A login's upstream tokens, handed to the receivers as federation hands them; the last receipt answered. */
	const receive = async (session: Session, given: Partial<UpstreamTokens> = {}, idp = "corp") => {
		const tokensGiven = { accessToken: "up-1", tokenType: "Bearer", scope: ["read"], ...given };
		let receipt: string | undefined;
		for (const one of receivers) {
			receipt = (await one.received({ session, idp, tokens: tokensGiven })) ?? undefined;
		}
		return receipt;
	};
	const call = async (
		step: string,
		token: string | undefined,
		more: {
			readonly idp?: string;
			readonly form?: Record<string, string>;
			readonly scheme?: string;
		} = {},
	) => {
		const scheme = more.scheme ?? "Bearer";
		const response: HttpResponse = await route.handle(
			testRequest({
				method: "POST",
				path: `/oauth/federation/${more.idp ?? "corp"}/${step}`,
				headers: new Map(token === undefined ? [] : [["authorization", `${scheme} ${token}`]]),
				form: new Map(Object.entries(more.form ?? {}).map(([k, v]) => [k, [v]])),
			}),
		);
		const body = response.body as { json?: Record<string, unknown> } | undefined;
		return { status: response.status, headers: response.headers ?? {}, json: body?.json };
	};
	return {
		app,
		input,
		/** Every route composed, for a test that drives another module's. */
		routes: all,
		stores,
		events: recorded.events,
		/** What the module logged. */
		logged: logged.lines,
		families,
		receivers,
		login,
		issue,
		receive,
		/** Calls the route's handler for `step` directly, past the policies the route uses. */
		call,
		/** Serves the composition over http, for a test of what the route uses before its handler. */
		listen: async () => {
			await app.start();
			return {
				url: `http://127.0.0.1:${app.get(listening).port()}`,
				stop: () => app.stop(1000),
			};
		},
		ask: (token: string | undefined, idp?: string) =>
			call("token", token, idp === undefined ? {} : { idp }),
		logout: (token: string, form: Record<string, string> = {}, idp?: string) =>
			call("logout", token, { form, ...(idp === undefined ? {} : { idp }) }),
		advance: (ms: number) => {
			now += ms;
		},
		now: () => now,
		close: (session: Session) => app.get(sessions).close(session.id),
		/** Makes the subject's sessions fall short of a requirement at use, open as they are. */
		shorten: (subject: string) => {
			short.add(subject);
		},
	};
}
