import { contract, defineModule } from "@mod/kernel";
import {
	type CredentialPolicy,
	credentialPolicy,
	DestinationRefused,
	hostList,
	type Narrower,
	type OutboundLimits,
	type OutboundRefusals,
	outboundLimits,
	outboundRefusals,
	policyOf,
	policySettings,
} from "@mod/outbound-policy";
import { isLoopbackName, urlSetting } from "@mod/url-setting";
import { z } from "zod";
import {
	type Outbound,
	type OutboundRequest,
	OutboundUnavailable,
	outbound,
	type SignedOutbound,
	signedOutbound,
} from "./contract.ts";
import { type Resolver, type Route, send, systemResolver, type Trust } from "./transport.ts";

export const section = policySettings
	.safeExtend({
		"max-concurrent": z
			.number()
			.int()
			.min(1)
			.max(1024)
			.prefault(16)
			.describe("Requests under way at once; one more is unavailable at once."),
		"direct-despite-proxy": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether to boot while a proxy variable is set and no proxy is configured; the variables are never read.",
			),
		proxy: urlSetting({ schemes: ["http"], origin: true })
			.optional()
			.describe(
				"The proxy every https request goes through by CONNECT, but to direct hosts; it resolves names and checks their addresses.",
			),
		"proxy-authorization": z
			.string()
			.regex(
				/^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/,
				"printable ASCII on one line, no space at either end",
			)
			.refine((value) => !value.startsWith("REPLACE-"), "a sample left in place")
			.optional()
			.describe(
				"The Proxy-Authorization value the proxy asks for, such as `Basic …`: printable ASCII on one line.",
			),
		"direct-hosts": hostList.describe(
			"The hosts reached directly while a proxy is set; `.name` covers the name and the names under it.",
		),
	})
	.refine((s) => s["proxy-authorization"] === undefined || s.proxy !== undefined, {
		message: "proxy-authorization is for a proxy: set proxy too",
		path: ["proxy-authorization"],
	});

const proxyVariables = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].flatMap((name) => [
	name,
	name.toLowerCase(),
]);

/** Runs at most `max` at once; one more is unavailable at once, and a place is given back however a run ends. */
function places(max: number) {
	let taken = 0;
	return async <T>(run: () => Promise<T>): Promise<T> => {
		if (taken >= max) throw new OutboundUnavailable("busy");
		taken++;
		try {
			return await run();
		} finally {
			taken--;
		}
	};
}

/** Node's threadpool when `UV_THREADPOOL_SIZE` sets none it can read. */
const defaultThreadpool = 4;

/**
 * How many names may resolve at once: half the threadpool, rounded up, at least one and never more
 * than `max-concurrent`. A lookup runs on the threadpool and no deadline stops it, so names that
 * answer slowly hold at most half of it, leaving the rest to hashing and the file system.
 */
export function lookupsAtOnce(threadpool: string | undefined, maxConcurrent: number): number {
	const size = /^[1-9]\d*$/.test(threadpool ?? "") ? Number(threadpool) : defaultThreadpool;
	return Math.min(maxConcurrent, Math.max(1, Math.floor((size + 1) / 2)));
}

interface Paths {
	readonly fetch: Outbound["fetch"];
	readonly fetchSigned: SignedOutbound["fetch"];
	readonly explained: OutboundRefusals["explained"];
	readonly credentialRefusalOf: CredentialPolicy["refusalOf"];
	readonly limitsOf: OutboundLimits["of"];
	readonly lookupsOf: NonNullable<OutboundLimits["lookupsOf"]>;
}

/** One header value: printable ASCII on one line, no space at either end. */
const headerValue = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;

/** The request as sent: its credential as the Authorization header; none for signed material. Its value is never told. */
function sentRequest(request: OutboundRequest, signed: boolean): OutboundRequest {
	const { credential, ...rest } = request;
	// An Authorization value goes only as a credential, under its rules: never one a caller writes.
	if (Object.keys(rest.headers ?? {}).some((name) => name.toLowerCase() === "authorization")) {
		throw new TypeError("outbound: an Authorization value goes as the request's credential");
	}
	if (credential === undefined) return rest;
	if (signed) throw new DestinationRefused("credential");
	if (!headerValue.test(credential)) {
		throw new TypeError("outbound: a credential is one header value, printable ASCII on one line");
	}
	return { ...rest, headers: { ...rest.headers, authorization: credential } };
}

/** The outbound paths over a resolver; the module passes the system's, a test its own. */
/** `deadlineOf` makes a request's one deadline; a test gives one it fires itself. */
export function outboundOver(
	settings: z.output<typeof section>,
	resolve: Resolver,
	trust: Trust = {},
	deadlineOf: (ms: number) => AbortSignal = AbortSignal.timeout,
	lookups = lookupsAtOnce(process.env.UV_THREADPOOL_SIZE, settings["max-concurrent"]),
): Paths {
	const policy = policyOf(settings);
	const direct = settings["direct-hosts"];
	const route: Route | undefined =
		settings.proxy === undefined
			? undefined
			: {
					proxy: new URL(settings.proxy),
					...(settings["proxy-authorization"]
						? { authorization: settings["proxy-authorization"] }
						: {}),
					direct: (host) => policy.listed(host, direct),
				};
	const requestPlace = places(settings["max-concurrent"]);
	// A name lookup cannot be stopped at a deadline: one still running past it holds a lookup of its
	// own, never a request's place, and no more run at once than half the threadpool. Names an outside
	// party chose take half of those at most, so slow ones of theirs never hold every lookup.
	const outsideLookups = Math.floor(lookups / 2);
	const outsidePlace = places(outsideLookups);
	const ownPlace = places(lookups - outsideLookups);
	// A name already resolving is answered by that lookup, which takes one place for all who ask.
	const resolving = new Map<string, Promise<readonly string[]>>();
	const boundedBy =
		(place: ReturnType<typeof places>): Resolver =>
		(host) =>
			resolving.get(host) ??
			place(() => {
				const lookup = resolve(host);
				resolving.set(host, lookup);
				return lookup.finally(() => resolving.delete(host));
			});
	const outsideChosen = boundedBy(outsidePlace);
	const own = boundedBy(ownPlace);
	const go = async (url: string, request: OutboundRequest, narrower: Narrower, signed: boolean) => {
		const limits = policy.limitsOf(narrower, signed);
		const sent = sentRequest(request, signed);
		const admitted = policy.admit(url, narrower, signed);
		const bounded = narrower.outsideChosen ? outsideChosen : own;
		return requestPlace(() =>
			send(admitted, sent, limits, bounded, policy, route, trust, deadlineOf),
		);
	};
	return {
		fetch: (url, request = {}, narrower = {}) => go(url, request, narrower, false),
		fetchSigned: (url, request, narrower) => go(url, request, narrower, true),
		credentialRefusalOf: policy.credentialRefusal,
		explained: policy.explain,
		// The call `go` cuts a request by, for a plain request.
		limitsOf: (narrower) => policy.limitsOf(narrower, false),
		lookupsOf: (narrower) => (narrower?.outsideChosen ? outsideLookups : lookups - outsideLookups),
	};
}

const paths = contract<Paths>("outbound.paths");

export default defineModule({ name: "outbound", section, replicaSafe: true }, (m) => [
	m.provide(paths).by((c) => {
		const { proxy } = c.section;
		// Their count alone: what goes to them, passwords, tokens, credentials and keys, is in the clear.
		const plainInternal = c.section["plain-internal"].length;
		if (plainInternal > 0) c.log.warn("outbound.plain_internal", { count: plainInternal });
		if (proxy !== undefined) {
			const host = new URL(proxy).hostname;
			c.log.warn("outbound.proxy_checks_addresses", { host });
			if (c.section["proxy-authorization"] && !isLoopbackName(host)) {
				c.log.warn("outbound.proxy_credentials_in_clear", { host });
			}
		}
		const present = proxyVariables.filter((name) => (process.env[name] ?? "") !== "");
		if (proxy === undefined && present.length > 0 && !c.section["direct-despite-proxy"]) {
			c.refuse(
				"outbound",
				`${present.join(", ")} is set and never read: write outbound.proxy, or declare direct-despite-proxy`,
			);
		}
		return outboundOver(c.section, systemResolver);
	}),
	// One set of counts for both paths.
	m.provide(outbound).by(async (c) => ({ fetch: (await c.get(paths)).fetch })),
	m.provide(signedOutbound).by(async (c) => ({ fetch: (await c.get(paths)).fetchSigned })),
	m.provide(outboundRefusals).by(async (c) => ({ explained: (await c.get(paths)).explained })),
	m.provide(credentialPolicy).by(async (c) => ({
		refusalOf: (await c.get(paths)).credentialRefusalOf,
	})),
	m.provide(outboundLimits).by(async (c) => {
		const { limitsOf, lookupsOf } = await c.get(paths);
		return { of: limitsOf, lookupsOf };
	}),
]);
