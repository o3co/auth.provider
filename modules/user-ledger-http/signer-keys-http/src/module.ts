import { signerKeys } from "@mod/jwt-bearer";
import { defineModule } from "@mod/kernel";
import { credentialPolicy, outbound, outboundRefusals } from "@mod/outbound";
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
		const refused = (await c.get(outboundRefusals)).explained(url, narrower);
		if (refused !== undefined) {
			return c.refuse(
				"signer-keys-http.keys-url",
				`outbound's destination policy refuses it: ${refused}`,
			);
		}
		const { credential } = c.section;
		if (credential !== undefined && (await c.get(credentialPolicy)).refusalOf([url])) {
			return c.refuse(
				"signer-keys-http.credential",
				"goes over https alone, or to a named plain-loopback pair",
			);
		}
		return keysAt({
			issuer: c.section.issuer,
			url,
			out: await c.get(outbound),
			credential,
			narrower,
			warn: (event, fields) => c.log.warn(event, fields),
		});
	}),
]);
