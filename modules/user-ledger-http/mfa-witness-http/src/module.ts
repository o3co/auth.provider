import { defineModule } from "@mod/kernel";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { outbound } from "@mod/outbound";
import {
	credentialPolicy,
	credentialRefusalText,
	destinationRefusal,
	outboundLimits,
	outboundRefusals,
} from "@mod/outbound-policy";
import { section } from "./section.ts";
import { witnessAt } from "./witness.ts";

export default defineModule({ name: "mfa-witness-http", section, replicaSafe: true }, (m) => [
	m.contribute(enrollmentWitnesses).by(async (c) => {
		const { "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
		const withdraw = c.section["withdraw-url"];
		const urls = {
			read: c.section["read-url"],
			enroll: c.section["enroll-url"],
			clear: c.section["clear-url"],
			...(withdraw === undefined ? {} : { withdraw }),
		};
		// The operator's own URLs, at one origin as their credential's rule holds them: reached at a
		// private address there alone, for a host in `internal-hosts` or a `plain-internal` pair.
		const narrower = {
			hosts: [...new Set(Object.values(urls).map((url) => new URL(url).hostname))],
			internal: urls.read,
			timeoutMs,
			...(maxBytes === undefined ? {} : { maxBytes }),
		};
		const refusals = await c.get(outboundRefusals);
		for (const [call, url] of Object.entries(urls)) {
			const refused = destinationRefusal(refusals, url, narrower);
			if (refused !== undefined) return c.refuse(`mfa-witness-http.${call}-url`, refused);
		}
		const refused = (await c.get(credentialPolicy)).refusalOf(Object.values(urls));
		if (refused !== undefined) {
			return c.refuse("mfa-witness-http.credential", credentialRefusalText(refused));
		}
		// Without it, the witness's own mark is cleared, a binding's beside it too; the operator is told.
		if (withdraw === undefined) c.log.warn("mfa-witness-http.withdraw_missing", {});
		return witnessAt({
			urls,
			out: await c.get(outbound),
			credential: c.section.credential,
			narrower,
			// What outbound holds a call to, not the section's timeout alone: outbound's own may be shorter.
			heldMs: (await c.get(outboundLimits)).of(narrower).timeoutMs,
			now: c.clock.now,
			warn: (event, fields) => c.log.warn(event, fields),
		});
	}),
]);
