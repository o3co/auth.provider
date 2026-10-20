import { auditReceivers } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import {
	credentialPolicy,
	credentialRefusalText,
	destinationRefusal,
	outboundRefusals,
} from "@mod/outbound-policy";
import { section } from "./section.ts";

export default defineModule({ name: "audit-http", section, replicaSafe: true }, (m) => [
	m.contribute(auditReceivers).by(async (c) => {
		const { url, authorization } = c.section;
		// The operator's own URL: a collector at a host in `internal-hosts` is reached at a private address at its origin.
		const own = { internal: url };
		const refused = destinationRefusal(await c.get(outboundRefusals), url, own);
		if (refused !== undefined) {
			return c.refuse("audit-http.url", refused);
		}
		const credentialRefused =
			authorization === undefined ? undefined : (await c.get(credentialPolicy)).refusalOf([url]);
		if (credentialRefused !== undefined) {
			const reason = `a secret Authorization value ${credentialRefusalText(credentialRefused)}`;
			return c.refuse("audit-http.url", reason);
		}
		const out = await c.get(outbound);
		const headers = { "content-type": "application/json" };
		const sent = authorization === undefined ? {} : { credential: authorization };
		return {
			name: "http",
			receive: async (event) => {
				const answer = await out.fetch(
					url,
					{ method: "POST", headers, body: JSON.stringify(event), ...sent },
					own,
				);
				if (answer.status < 200 || answer.status > 299) {
					throw new Error(`audit-http: the collector answered ${answer.status}`);
				}
			},
		};
	}),
]);
