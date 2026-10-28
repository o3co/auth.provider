import { certificateForwarding } from "@mod/client-certificate";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { signedOutbound } from "@mod/outbound";
import { senderBindings } from "@mod/sender-binding";
import { type Checking, readCertificate } from "./binding.ts";
import { pkiOver } from "./pki/pki.ts";
import { anchorOf, revocationPolicyOf, section } from "./section.ts";
import { sourcesOver } from "./sources.ts";

export default defineModule(
	// Safe on many instances: each keeps its own revocation caches up to their limits (`crl-ttl`, `ocsp-fresh`,
	// `failure-lifetime`); hosts may disagree within them, as one host does over time.
	{ name: "mtls", replicaSafe: true, section, takes: [certificateForwarding, signedOutbound] },
	(m) => [
		m.contribute(senderBindings).by(async (c) => {
			if (!(await c.get(certificateForwarding)).configured) {
				c.refuse("mtls", "http forwards no client certificate: name its client-certificate form");
			}
			const s = c.section;
			let pki: Checking["pki"];
			if (s.mode === "pki") {
				const anchors = s.anchors.map(anchorOf).filter((der) => der !== undefined);
				if (anchors.length < s.anchors.length) {
					c.refuse("mtls.anchors", "each anchor is one certificate in PEM");
				}
				const policy = {
					anchors,
					maxIntermediates: s["max-intermediates"],
					minRsaBits: s["min-rsa-bits"],
				};
				const r = s.revocation;
				pki =
					r.mode === "disabled"
						? // Nothing is fetched, so no outage is ever left to the operator.
							{ checks: pkiOver(policy), onUnavailable: "reject" }
						: {
								checks: pkiOver(policy, {
									policy: revocationPolicyOf(r),
									sources: sourcesOver(
										await c.get(signedOutbound),
										{ hosts: r.hosts, timeoutMs: r.timeout },
										{ now: () => c.clock.now(), random: (n) => c.random.bytes(n) },
									),
								}),
								onUnavailable: r["on-unavailable"],
							};
			}
			const checking: Checking = {
				now: () => c.clock.now(),
				log: (event, fields) => c.log.warn(event, fields),
				...(pki ? { pki } : {}),
			};
			return {
				member: "x5t#S256",
				name: "mtls",
				tokenType: "Bearer",
				read: (request, scene) =>
					readCertificate(request.source.clientCertificate, scene, checking),
			};
		}),
		m.contribute(metadata).by(() => ({
			name: "tls_client_certificate_bound_access_tokens",
			value: true,
		})),
	],
);
