import { isLoopbackAddress } from "@mod/address-reach";
import { contract, defineModule } from "@mod/kernel";
import {
	type CredentialPolicy,
	credentialPolicy,
	hostList,
	type Narrower,
	type OutboundLimits,
	type OutboundRefusals,
	outboundLimits,
	outboundRefusals,
	policyOf,
	policySettings,
} from "@mod/outbound-policy";
import { isFloor, tlsOptions } from "@mod/tls-options";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";
import {
	type Outbound,
	type OutboundRequest,
	OutboundUnavailable,
	outbound,
	type SignedOutbound,
	signedOutbound,
} from "./contract.ts";
import { sentRequest } from "./credential/credential.ts";
import {
	inProcessPool,
	LookupRefused,
	type Lookups,
	lookupShares,
	lookupsOver,
	type Pool,
} from "./lookups/contract.ts";
import { plainIpv4Rules, plainIpv4Setting, takesIpv4 } from "./plain-ipv4.ts";
import { type ResolverPool, resolverPool } from "./resolver-process/contract.ts";
import type { Tls } from "./tls/tls.ts";
import { type Lookup, type Resolver, type Route, send, systemLookup } from "./transport.ts";

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
		"plain-ipv4": plainIpv4Setting,
		resolution: z
			.enum(["helper", "in-process"])
			.prefault("helper")
			.describe(
				"Where names are resolved, as the system resolves them: `helper`, in helper processes, one ended once no request waits on its lookups; `in-process`, here, where no deadline stops a lookup.",
			),
		"max-lookups": z
			.number()
			.int()
			.min(1)
			.max(1024)
			.optional()
			.describe(
				"Names resolving at once, the outside party's half among them; one more is unavailable at once. Four by default, never more than max-concurrent.",
			),
	})
	.refine((s) => s["max-lookups"] === undefined || s["max-lookups"] <= s["max-concurrent"], {
		message: "max-lookups is never more than max-concurrent",
		path: ["max-lookups"],
	})
	.refine((s) => s["proxy-authorization"] === undefined || s.proxy !== undefined, {
		message: "proxy-authorization is for a proxy: set proxy too",
		path: ["proxy-authorization"],
	})
	.superRefine((s, context) => {
		for (const [holds, message] of plainIpv4Rules) {
			if (!holds(s)) context.addIssue({ code: "custom", message, path: ["plain-ipv4"] });
		}
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

/** Names resolving at once: the setting, else four, never more than `max-concurrent`. */
const maxLookupsOf = (settings: z.output<typeof section>) =>
	settings["max-lookups"] ?? Math.min(4, settings["max-concurrent"]);

/** The two pools a section's lookups run in, the deployment's own and the outside party's, and their shares. */
export interface LookupPools {
	readonly own: Pool;
	readonly outside: Pool;
	readonly shares: { readonly own: number; readonly outside: number };
}

/** A pool of no place: an outside party's where its share is none. */
const noPool: Pool = { run: () => undefined };

/** A pool's lookups as a request's resolver: their refusals as outbound's own. */
const resolverOf =
	(lookups: Lookups, family?: 4): Resolver =>
	(name, signal) =>
		lookups.resolve(name, family, signal).catch((error: unknown) => {
			if (!(error instanceof LookupRefused)) throw error;
			throw new OutboundUnavailable(error.failure === "unavailable" ? "busy" : error.failure);
		});

interface Paths {
	readonly fetch: Outbound["fetch"];
	readonly fetchSigned: SignedOutbound["fetch"];
	readonly explained: OutboundRefusals["explained"];
	readonly plainInternal: NonNullable<OutboundRefusals["plainInternal"]>;
	readonly browsedRefusal: NonNullable<OutboundRefusals["browsedRefusal"]>;
	readonly credentialRefusalOf: CredentialPolicy["refusalOf"];
	readonly limitsOf: OutboundLimits["of"];
	readonly lookupsOf: NonNullable<OutboundLimits["lookupsOf"]>;
}

/** A floor not tls-options' own handed to `outboundOver`: the composition is wrong, not a setting. */
export class NotTheFloor extends TypeError {
	constructor() {
		super("the TLS floor is not one tls-options made: provide it from @mod/tls-options");
	}
}

/** The outbound paths over a resolver; the module passes the system's, a test its own. */
/** `deadlineOf` makes a request's one deadline; a test gives one it fires itself. */
export function outboundOver(
	settings: z.output<typeof section>,
	/** The pools to resolve in; a lookup function, as a test gives, runs in this process. */
	lookupsIn: LookupPools | Lookup,
	/** The floor every TLS connection holds to, and a test's authorities. */
	tls: Tls,
	deadlineOf: (ms: number) => AbortSignal = AbortSignal.timeout,
	/** In this process, the lookups at once; else as the settings and the threadpool give. */
	lookupsAtOnce?: number,
): Paths {
	// A copy of the floor, or another's value, may carry a weaker one: tls-options' own alone is taken.
	if (!isFloor(tls.floor)) throw new NotTheFloor();
	const pools =
		typeof lookupsIn === "function"
			? inProcessPools(settings, lookupsIn, lookupsAtOnce)
			: lookupsIn;
	const own = lookupsOver(pools.own);
	const outside = lookupsOver(pools.outside);
	const policy = policyOf(settings);
	const direct = settings["direct-hosts"];
	const route: Route | undefined =
		settings.proxy === undefined
			? undefined
			: {
					proxy: new URL(settings.proxy),
					// The proxy is the deployment's own: its name resolves in the deployment's pool.
					resolve: resolverOf(own),
					...(settings["proxy-authorization"]
						? { authorization: settings["proxy-authorization"] }
						: {}),
					direct: (host) => policy.listed(host, direct),
				};
	const requestPlace = places(settings["max-concurrent"]);
	const go = async (url: string, request: OutboundRequest, narrower: Narrower, signed: boolean) => {
		const limits = policy.limitsOf(narrower, signed);
		const sent = sentRequest(request, signed);
		const admitted = policy.admit(url, narrower, signed);
		// Names an outside party chose resolve in a pool of their own, so theirs never hold every lookup.
		// A plain-ipv4 pair's name is resolved for IPv4 alone; the policy checks every answer as ever.
		const resolving = resolverOf(
			narrower.outsideChosen ? outside : own,
			takesIpv4(settings["plain-ipv4"], admitted) ? 4 : undefined,
		);
		return requestPlace(() =>
			send(admitted, sent, limits, resolving, policy, route, tls, deadlineOf),
		);
	};
	return {
		fetch: (url, request = {}, narrower = {}) => go(url, request, narrower, false),
		fetchSigned: (url, request, narrower) => go(url, request, narrower, true),
		credentialRefusalOf: policy.credentialRefusal,
		explained: policy.explain,
		plainInternal: policy.plainInternal,
		browsedRefusal: policy.browsedRefusal,
		// The call `go` cuts a request by, for a plain request.
		limitsOf: (narrower) => policy.limitsOf(narrower, false),
		lookupsOf: (narrower) => (narrower?.outsideChosen ? pools.shares.outside : pools.shares.own),
	};
}

/**
 * Lookups in this process with `lookup`: the shares of `lookupsAtOnce` where given, else of
 * `max-lookups` held to half the threadpool.
 */
function inProcessPools(
	settings: z.output<typeof section>,
	lookup: Lookup,
	lookupsAtOnce?: number,
): LookupPools {
	const shares =
		lookupsAtOnce === undefined
			? lookupShares({
					maxLookups: maxLookupsOf(settings),
					inProcess: { threadpool: process.env.UV_THREADPOOL_SIZE },
				})
			: lookupShares({ maxLookups: lookupsAtOnce });
	return {
		own: inProcessPool(shares.own, lookup),
		outside: shares.outside > 0 ? inProcessPool(shares.outside, lookup) : noPool,
		shares,
	};
}

const paths = contract<Paths>("outbound.paths");

export default defineModule(
	{ name: "outbound", section, replicaSafe: true, takes: [tlsOptions] },
	(m) => [
		m.provide(paths).by(async (c) => {
			const tls = { floor: await c.get(tlsOptions) };
			/** The paths over these lookups, a floor not tls-options' own refusing boot as composed wrong. */
			const over = (lookups: LookupPools | Lookup) => {
				try {
					return outboundOver(c.section, lookups, tls);
				} catch (error) {
					if (error instanceof NotTheFloor) return c.refuse("outbound", error.message);
					throw error;
				}
			};
			const { proxy } = c.section;
			// Their count alone: what goes to them, passwords, tokens, credentials and keys, is in the clear.
			const plainInternal = c.section["plain-internal"].length;
			if (plainInternal > 0) c.log.warn("outbound.plain_internal", { count: plainInternal });
			if (proxy !== undefined) {
				const host = new URL(proxy).hostname;
				c.log.warn("outbound.proxy_checks_addresses", { host });
				if (c.section["proxy-authorization"] && !isLoopbackAddress(host)) {
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
			if (c.section.resolution === "in-process") return over(systemLookup);
			// Each pool's helper is started here; a refused start ends both before boot is refused.
			const shares = lookupShares({ maxLookups: maxLookupsOf(c.section) });
			const poolOf = (pool: string, size: number) =>
				resolverPool({ pool, size, warn: c.log.warn, now: () => c.clock.now() });
			const started: ResolverPool[] = [poolOf("own", shares.own)];
			if (shares.outside > 0) started.push(poolOf("outside", shares.outside));
			const stopAll = () => Promise.all(started.map((pool) => pool.stop())).then(() => {});
			c.onStop(stopAll);
			try {
				await Promise.all(started.map((pool) => pool.start()));
			} catch {
				await stopAll();
				c.refuse(
					"outbound.resolution",
					"the resolver's helper process did not start: allow it to start, or set resolution = in-process",
				);
			}
			const [ownPool, outsidePool] = started as [ResolverPool, ResolverPool?];
			return over({ own: ownPool, outside: outsidePool ?? noPool, shares });
		}),
		// One set of counts for both paths.
		m.provide(outbound).by(async (c) => ({ fetch: (await c.get(paths)).fetch })),
		m.provide(signedOutbound).by(async (c) => ({ fetch: (await c.get(paths)).fetchSigned })),
		m.provide(outboundRefusals).by(async (c) => {
			const { explained, plainInternal, browsedRefusal } = await c.get(paths);
			return { explained, plainInternal, browsedRefusal };
		}),
		m.provide(credentialPolicy).by(async (c) => ({
			refusalOf: (await c.get(paths)).credentialRefusalOf,
		})),
		m.provide(outboundLimits).by(async (c) => {
			const { limitsOf, lookupsOf } = await c.get(paths);
			return { of: limitsOf, lookupsOf };
		}),
	],
);
