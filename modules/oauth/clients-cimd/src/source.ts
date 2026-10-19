import type { ClientSource } from "@mod/clients";
import { codeGrantType } from "@mod/code-grant";
import { composedGrants } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { withinHosts } from "@mod/outbound-policy";
import { documentUrl } from "./document/document.ts";
import { readingOver } from "./document/reading.ts";
import { fetchingOver } from "./fetching/fetching.ts";
import type { Settings } from "./section.ts";

/** Whether document clients are taken: only with the code grant composed. */
export const supportedOver = async (c: BuildContext<Settings>) =>
	(await c.get(composedGrants)).has(codeGrantType) ? true : undefined;

/** The client source: an id's form and host first, then the kept or fetched document. */
export async function sourceOver(c: BuildContext<Settings>): Promise<ClientSource> {
	const s = c.section;
	const composed = c.late(composedGrants);
	const fetching = fetchingOver(
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
