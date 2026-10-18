import { signerKeys } from "@mod/jwt-bearer";
import { defineModule } from "@mod/kernel";
import { outbound, outboundPolicy } from "@mod/outbound";
import { keysAt } from "./lookup.ts";
import { section } from "./section.ts";

export default defineModule({ name: "signer-keys-http", section, replicaSafe: true }, (m) => [
	m.contribute(signerKeys).by(async (c) => {
		const { "keys-url": url, "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
		// The operator's own URL: a host in `internal-hosts` is reached at a private address.
		const narrower = {
			hosts: [new URL(url).hostname],
			internal: true as const,
			...(maxBytes === undefined ? {} : { maxBytes }),
			...(timeoutMs === undefined ? {} : { timeoutMs }),
		};
		const refusal = (await c.get(outboundPolicy)).refusalOf(url, narrower);
		if (refusal !== undefined) {
			return c.refuse(
				"signer-keys-http.keys-url",
				`outbound's destination policy refuses it: ${refusal}`,
			);
		}
		return keysAt({
			issuer: c.section.issuer,
			url,
			out: await c.get(outbound),
			credential: c.section.credential,
			narrower,
			warn: (event, fields) => c.log.warn(event, fields),
		});
	}),
]);
