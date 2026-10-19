import { isIP } from "node:net";
import { contract, defineModule, setting } from "@mod/kernel";
import { z } from "zod";
import {
	type CredentialPolicy,
	credentialPolicy,
	DestinationRefused,
	type Narrower,
	type Outbound,
	type OutboundRefusals,
	type OutboundRequest,
	OutboundUnavailable,
	outbound,
	outboundRefusals,
	type RefusalReason,
	type SignedOutbound,
	signedOutbound,
} from "./contract.ts";
import {
	admitAddresses,
	admitUrl,
	credentialRefusal,
	isHostEntry,
	isListEntry,
	isPair,
	listed,
	remedyOf,
} from "./policy.ts";
import { type Resolver, type Route, send, systemResolver, type Trust } from "./transport.ts";

const hostEntries = z.array(z.string().refine(isHostEntry, "not a host")).prefault([]);
const listEntries = z
	.array(z.string().refine(isListEntry, "not a host, or a name led by a dot"))
	.prefault([]);

/** An http origin, as written and as read alike: no credentials, path, query or stray character. */
const isProxyOrigin = (value: string) => {
	if (/[\s\p{Cc}]/u.test(value)) return false;
	const url = URL.parse(value);
	return (
		url?.protocol === "http:" &&
		url.username === "" &&
		url.password === "" &&
		url.hostname !== "" &&
		(value === url.origin || value === `${url.origin}/`)
	);
};
const isLoopbackHost = (host: string) =>
	host === "localhost" || host === "[::1]" || (isIP(host) === 4 && host.startsWith("127."));
export const section = z
	.strictObject({
		allow: hostEntries.describe(
			"The hosts requests may reach by name; `.name` covers the name and the names under it.",
		),
		"allow-any-public": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether requests may reach any host at a public address, instead of naming hosts in `allow`.",
			),
		deny: hostEntries.describe(
			"The hosts requests never reach, checked before `allow`; `.name` covers the name and the names under it.",
		),
		"plain-loopback": z
			.array(z.string().refine(isPair, "not a host:port pair"))
			.prefault([])
			.describe("The `host:port` pairs plain http may reach at loopback addresses."),
		"max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.prefault("64KiB")
			.describe("The largest response body a request takes, from 1B to 16MiB."),
		"signed-max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.prefault("1MiB")
			.describe("The largest response body a request for signed material takes, from 1B to 16MiB."),
		timeout: setting
			.duration("ms")
			.pipe(z.number().int().min(1).max(60_000))
			.prefault("5s")
			.describe(
				"The one deadline covering a request's resolving, connecting, headers and body, from 1ms to 1m.",
			),
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
		proxy: z
			.string()
			.refine(isProxyOrigin, "an http origin, without credentials, path or query")
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
		"direct-hosts": listEntries.describe(
			"The hosts reached directly while a proxy is set; `.name` covers the name and the names under it.",
		),
		"internal-hosts": listEntries.describe(
			"The hosts a URL from the operator's own configuration may reach at a private address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7); `.name` covers the name and the names under it.",
		),
	})
	.refine((s) => !(s["allow-any-public"] && s.allow.length > 0), {
		message: "allow-any-public reaches any public address; name hosts in allow or set it, not both",
	})
	.refine((s) => s["proxy-authorization"] === undefined || s.proxy !== undefined, {
		message: "proxy-authorization is for a proxy: set proxy too",
		path: ["proxy-authorization"],
	});

const proxyVariables = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].flatMap((name) => [
	name,
	name.toLowerCase(),
]);

/** A narrower's number, which only a caller's mistake makes other than positive and finite. */
const narrowing = (value: number | undefined): number => {
	if (value === undefined) return Number.POSITIVE_INFINITY;
	if (value > 0 && Number.isFinite(value)) return value;
	throw new RangeError("outbound: a narrower's numbers are positive and finite");
};

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

interface Paths {
	readonly fetch: Outbound["fetch"];
	readonly fetchSigned: SignedOutbound["fetch"];
	readonly explained: OutboundRefusals["explained"];
	readonly credentialRefusalOf: CredentialPolicy["refusalOf"];
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
): Paths {
	const policy = {
		allow: settings.allow,
		anyPublic: settings["allow-any-public"],
		deny: settings.deny,
		plainLoopback: settings["plain-loopback"],
		internal: settings["internal-hosts"],
	};
	const direct = settings["direct-hosts"];
	const route: Route | undefined =
		settings.proxy === undefined
			? undefined
			: {
					proxy: new URL(settings.proxy),
					...(settings["proxy-authorization"]
						? { authorization: settings["proxy-authorization"] }
						: {}),
					direct: (host) => listed(host, direct),
				};
	const requestPlace = places(settings["max-concurrent"]);
	const lookupPlace = places(settings["max-concurrent"]);
	// A name lookup cannot be stopped at a deadline: one still running past it holds a lookup of its
	// own, never a request's place, and no more run at once than requests may.
	const bounded: Resolver = (host) => lookupPlace(() => resolve(host));
	const go = async (url: string, request: OutboundRequest, narrower: Narrower, signed: boolean) => {
		const limits = {
			maxBytes: Math.min(
				settings[signed ? "signed-max-response-size" : "max-response-size"],
				narrowing(narrower.maxBytes),
			),
			timeoutMs: Math.min(settings.timeout, narrowing(narrower.timeoutMs)),
		};
		const sent = sentRequest(request, signed);
		const admitted = admitUrl(url, policy, narrower, signed);
		return requestPlace(() => send(admitted, sent, limits, bounded, route, trust, deadlineOf));
	};
	/** Why the policy refuses the URL, or undefined when it lets it through; no name is resolved. */
	const refusalOf = (url: string, narrower: Narrower = {}): RefusalReason | undefined => {
		try {
			const admitted = admitUrl(url, policy, narrower, false);
			// An address written in the URL is checked now; a name's, once resolved, when sent.
			if (isIP(admitted.host) !== 0) admitAddresses([admitted.host], admitted);
			return undefined;
		} catch (error) {
			if (error instanceof DestinationRefused) return error.reason;
			throw error;
		}
	};
	return {
		fetch: (url, request = {}, narrower = {}) => go(url, request, narrower, false),
		fetchSigned: (url, request, narrower) => go(url, request, narrower, true),
		credentialRefusalOf: (urls) => credentialRefusal(urls, policy.plainLoopback),
		explained: (url, narrower = {}) => {
			const reason = refusalOf(url, narrower);
			return reason && `${reason}: ${remedyOf(reason, url, policy, narrower)}`;
		},
	};
}

const paths = contract<Paths>("outbound.paths");

export default defineModule({ name: "outbound", section, replicaSafe: true }, (m) => [
	m.provide(paths).by((c) => {
		const { proxy } = c.section;
		if (proxy !== undefined) {
			const host = new URL(proxy).hostname;
			c.log.warn("outbound.proxy_checks_addresses", { host });
			if (c.section["proxy-authorization"] && !isLoopbackHost(host)) {
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
]);
