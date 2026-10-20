import { defineModule } from "@mod/kernel";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { outbound } from "@mod/outbound";
import {
	credentialPolicy,
	destinationRefusal,
	outboundLimits,
	outboundRefusals,
} from "@mod/outbound-policy";
import { section } from "./section.ts";
import { witnessAt } from "./witness.ts";

/** Why the credential may not go to the three URLs, as the operator reads it. */
const credentialRefused = {
	origins: "goes to one origin alone: read-url, enroll-url and clear-url must share it",
	scheme: "goes over https alone, or to a named plain-loopback pair",
} as const;

export default defineModule({ name: "mfa-witness-http", section, replicaSafe: true }, (m) => [
	m.contribute(enrollmentWitnesses).by(async (c) => {
		const { "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
		const urls = {
			read: c.section["read-url"],
			enroll: c.section["enroll-url"],
			clear: c.section["clear-url"],
		};
		// The operator's own URLs, at one origin as their credential's rule holds them: a host in
		// `internal-hosts` is reached at a private address there alone.
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
			return c.refuse("mfa-witness-http.credential", credentialRefused[refused]);
		}
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
