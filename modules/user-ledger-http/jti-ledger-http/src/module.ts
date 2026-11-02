import { jtiLedgers } from "@mod/jwt-bearer";
import { defineModule } from "@mod/kernel";
import { credentialHeaderRefusal, outbound } from "@mod/outbound";
import {
	credentialPolicy,
	credentialRefusalText,
	destinationRefusal,
	outboundRefusals,
} from "@mod/outbound-policy";
import { ledgerAt } from "./ledger.ts";
import { section } from "./section.ts";

export default defineModule(
	{
		name: "jti-ledger-http",
		section,
		replicaSafe: true,
		takes: [outbound, credentialPolicy, outboundRefusals],
	},
	(m) => [
		m.contribute(jtiLedgers).by(async (c) => {
			const { "consume-url": url, "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
			// The operator's own URL: reached at a private address at its origin, for a host in
			// `internal-hosts` or a `plain-internal` pair.
			const narrower = {
				hosts: [new URL(url).hostname],
				internal: url,
				...(maxBytes === undefined ? {} : { maxBytes }),
				...(timeoutMs === undefined ? {} : { timeoutMs }),
			};
			const refused = destinationRefusal(await c.get(outboundRefusals), url, narrower);
			if (refused !== undefined) return c.refuse("jti-ledger-http.consume-url", refused);
			const { credential, "credential-header": header } = c.section;
			if (header !== undefined) {
				const named =
					credential === undefined
						? "names the header a credential goes in, and no credential is set"
						: credentialHeaderRefusal(header);
				if (named !== undefined) return c.refuse("jti-ledger-http.credential-header", named);
			}
			const credentialRefused =
				credential === undefined ? undefined : (await c.get(credentialPolicy)).refusalOf([url]);
			if (credentialRefused !== undefined) {
				return c.refuse("jti-ledger-http.credential", credentialRefusalText(credentialRefused));
			}
			return ledgerAt({
				issuer: c.section.issuer,
				url,
				out: await c.get(outbound),
				credential,
				credentialHeader: header,
				narrower,
				warn: (event, fields) => c.log.warn(event, fields),
			});
		}),
	],
);
