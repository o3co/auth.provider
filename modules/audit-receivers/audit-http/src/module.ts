import { auditReceivers } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { outbound, outboundPolicy } from "@mod/outbound";
import { section } from "./section.ts";

/** The URL is the operator's own, so a collector at a host in `internal-hosts` is reached at a private address. */
const own = { internal: true } as const;

export default defineModule({ name: "audit-http", section, replicaSafe: true }, (m) => [
	m.contribute(auditReceivers).by(async (c) => {
		const { url, authorization } = c.section;
		const refusal = (await c.get(outboundPolicy)).refusalOf(url, own);
		if (refusal !== undefined) {
			return c.refuse("audit-http.url", `outbound's destination policy refuses it: ${refusal}`);
		}
		const out = await c.get(outbound);
		const headers = {
			"content-type": "application/json",
			...(authorization === undefined ? {} : { authorization }),
		};
		return {
			name: "http",
			receive: async (event) => {
				const answer = await out.fetch(
					url,
					{ method: "POST", headers, body: JSON.stringify(event) },
					own,
				);
				if (answer.status < 200 || answer.status > 299) {
					throw new Error(`audit-http: the collector answered ${answer.status}`);
				}
			},
		};
	}),
]);
