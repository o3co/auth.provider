import { createHash } from "node:crypto";
import type { Loads } from "../contract.ts";

/** Every answer's policy: nothing by default; scripts and images from this origin, styles and fonts over https too; no one frames it. */
const policy = [
	"default-src 'none'",
	"base-uri 'self'",
	"font-src 'self' https: data:",
	"form-action 'self'",
	"frame-ancestors 'none'",
	"img-src 'self' data:",
	"object-src 'none'",
	"script-src 'self'",
	"script-src-attr 'none'",
	"style-src 'self' https: 'unsafe-inline'",
	"upgrade-insecure-requests",
].join(";");

/** The headers besides the policy that every answer carries, as http sets them. */
const fixed: Readonly<Record<string, string>> = Object.freeze({
	"cross-origin-opener-policy": "same-origin",
	"cross-origin-resource-policy": "same-origin",
	"origin-agent-cluster": "?1",
	"referrer-policy": "no-referrer",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"x-content-type-options": "nosniff",
	"x-dns-prefetch-control": "off",
	"x-download-options": "noopen",
	"x-frame-options": "SAMEORIGIN",
	"x-permitted-cross-domain-policies": "none",
	"x-xss-protection": "0",
});

/** An origin a policy's host source can name: no IPv6 literal, no `_`, nothing after the port. */
const framable = /^https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?$/;

/** A page's policy: its frames and scripts, and nothing else. Throws on a frame it cannot name. */
function pagePolicy(loads: Loads): string {
	const frames = [...new Set(loads.frames)];
	if (!frames.every((frame) => framable.test(frame))) throw new TypeError("unnamable frame");
	const scripts = (loads.scripts ?? []).map(
		(text) => `'sha256-${createHash("sha256").update(text).digest("base64")}'`,
	);
	return [
		"default-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
		...(frames.length ? [`frame-src ${frames.join(" ")}`] : []),
		...(scripts.length ? [`script-src ${scripts.join(" ")}`] : []),
	].join("; ");
}

/** The answer's headers, the security headers and the policy in place of the route's. */
export function secured<V>(
	headers: Readonly<Record<string, V>>,
	loads?: Loads,
): Record<string, V | string> {
	const own = Object.entries(headers).filter(([name]) => {
		const lower = name.toLowerCase();
		return !Object.hasOwn(fixed, lower) && lower !== "content-security-policy";
	});
	return {
		...fixed,
		"content-security-policy": loads ? pagePolicy(loads) : policy,
		...Object.fromEntries(own),
	};
}
