import type { ClientSource } from "@mod/clients";
import { codeGrantType } from "@mod/code-grant";
import { composedGrants } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { outboundLimits, withinHosts } from "@mod/outbound-policy";
import { documentUrl } from "./document/document.ts";
import { readingOver, readingTakes } from "./document/reading.ts";
import { fetchingWith } from "./fetching/fetching.ts";
import type { Settings } from "./section.ts";

/** What `supportedOver` and `sourceOver` take from the build context. */
export const sourceTakes = [...readingTakes, outboundLimits, composedGrants] as const;

/** Whether document clients are taken: only with the code grant composed. */
export const supportedOver = async (c: BuildContext<Settings>) =>
	(await c.get(composedGrants)).has(codeGrantType) ? true : undefined;

/**
 * Refuses boot where the size or the timeout is above outbound's cap, naming the key, never a value,
 * or where outbound gives the names a document chooses no lookup.
 */
const withinOutbound = async (c: BuildContext<Settings>) => {
	const limits = await c.get(outboundLimits);
	const caps = limits.of();
	const above = (key: string, raise: string) => ({
		where: `clients-cimd.${key}`,
		reason: `is above outbound's cap: lower it, or raise outbound.${raise}`,
	});
	const refusals = [
		...(c.section["max-size"] > caps.maxBytes ? [above("max-size", "max-response-size")] : []),
		...(c.section.timeout > caps.timeoutMs ? [above("timeout", "timeout")] : []),
		// Given none, every document's fetch would answer unavailable.
		...(limits.lookupsOf?.({ outsideChosen: true }) === 0
			? [
					{
						where: "clients-cimd",
						reason:
							"outbound resolves no name a metadata document chooses: set outbound.max-lookups to 2 or more (and, resolving in process, UV_THREADPOOL_SIZE to 4 or more)",
					},
				]
			: []),
	];
	if (refusals.length > 0) c.refuseAll(refusals);
};

/**
 * Refuses boot unless the operator chose the document hosts: allow names them, or allow-any-host takes
 * any, never both. Warns at every start of any host taken.
 */
const hostsChosen = (c: BuildContext<Settings>) => {
	const s = c.section;
	if (!s["allow-any-host"]) {
		if (s.allow.length === 0) {
			c.refuse(
				"clients-cimd.allow",
				"is empty: name the hosts a client id's document may come from, or set clients-cimd.allow-any-host",
			);
		}
		return;
	}
	if (s.allow.length > 0) {
		c.refuse("clients-cimd.allow-any-host", "is set beside allow: keep one of them");
	}
	c.log.warn("clients-cimd.any_host_allowed", {});
};

/** The client source: an id's form and host first, then the kept or fetched document. */
export async function sourceOver(c: BuildContext<Settings>): Promise<ClientSource> {
	await withinOutbound(c);
	hostsChosen(c);
	const s = c.section;
	const composed = c.late(composedGrants);
	const fetching = fetchingWith(
		await readingOver(c),
		{
			cacheMs: s["cache-lifetime"] * 1000,
			entries: s["cache-entries"],
			refusedMs: s["refused-lifetime"] * 1000,
			concurrent: s["max-concurrent"],
		},
		c.clock,
	);
	/** A refused host is logged by the host alone: the id's other parts are the requester's text. */
	const hostRefused = (url: URL, reason: string) => {
		c.log.warn("clients-cimd.host_refused", { host: url.hostname, reason });
		return undefined;
	};
	return {
		// A document URL is exactly the URL fetched, cached and compared with its client_id.
		find: async (id) => {
			const url = composed().has(codeGrantType) ? documentUrl(id) : undefined;
			if (!url) return undefined;
			if (withinHosts(id, s.deny)) return hostRefused(url, "denied");
			if (s.allow.length > 0 && !withinHosts(id, s.allow)) return hostRefused(url, "not allowed");
			return fetching.find(id);
		},
	};
}
