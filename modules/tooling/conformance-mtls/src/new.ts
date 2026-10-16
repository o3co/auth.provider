import { onNew } from "@mod/conformance";
import { mtlsArea } from "./area.ts";

onNew(mtlsArea, (part) => {
	const revocation = part.pki?.revocation;
	const hosts = revocation?.sources.map((source) => new URL(`http://${source}`).hostname) ?? [];
	return {
		modules: ["@mod/mtls", "@mod/discovery", ...(revocation ? ["@mod/outbound"] : [])],
		config: {
			http: {
				"trusted-proxies": part.trustedProxies,
				"client-certificate": { dialect: part.header.dialect, header: part.header.name },
			},
			mtls: part.pki
				? {
						mode: "pki",
						anchors: part.pki.anchors,
						revocation: revocation
							? {
									mode: revocation.mode,
									"on-unavailable": revocation.onUnavailable,
									hosts,
								}
							: { mode: "disabled" },
					}
				: { mode: "self-signed" },
			// The sources are named so outbound reaches them, on plain http at loopback.
			...(revocation ? { outbound: { allow: hosts, "plain-loopback": revocation.sources } } : {}),
		},
	};
});
