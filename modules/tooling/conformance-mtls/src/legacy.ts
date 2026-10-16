import { onLegacy } from "@mod/conformance-legacy";
import { type MtlsPart, mtlsArea } from "./area.ts";

/** The legacy mTLS section for a part: the header from a trusted proxy, self-signed or full PKI. */
function settings(part: MtlsPart): string {
	const revocation = part.pki?.revocation;
	const lines = [
		"enabled = true",
		'source = "header"',
		`certHeader = ${JSON.stringify(part.header.name)}`,
		`certHeaderDialect = ${part.header.dialect === "xfcc" ? '"envoy"' : '"plain-pem"'}`,
		`trustedProxies = ${JSON.stringify(part.trustedProxies)}`,
		`mode = ${part.pki ? '"full-pki"' : '"self-signed"'}`,
		...(part.pki
			? [
					`trustedCas = ${JSON.stringify(part.pki.anchors)}`,
					revocation
						? `fullPki.revocation { mode = ${JSON.stringify(revocation.mode)}, onUnavailable = ${JSON.stringify(revocation.onUnavailable)}, allowedHosts = ${JSON.stringify(revocation.sources)} }`
						: 'fullPki.revocation { mode = "disabled" }',
				]
			: []),
	];
	return `mtls {\n${lines.join("\n")}\n}\n`;
}

onLegacy(mtlsArea, {
	// The standalone build does not load mTLS; the composed entry adds it.
	map: (part) => ({ settings: settings(part), extra: ["mtls"] }),
});
