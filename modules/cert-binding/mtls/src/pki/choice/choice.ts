import { X509Certificate } from "node:crypto";
import * as pkijs from "pkijs";
import { decoded } from "../der.ts";

/**
 * The most certificates a client may send, short of a path's intermediates, and issuers one
 * certificate may have.
 */
const most = { sent: 10, edges: 4 } as const;

/** A certificate as a choice reads it: its DER, that DER as a key, and node's reading. */
interface Read {
	readonly der: Uint8Array;
	readonly key: string;
	readonly x509: X509Certificate;
}

/** A certificate read; none for anything that is not one, as node and pkijs both read it. */
function readOf(der: Uint8Array): Read | undefined {
	if (!decoded(der, (schema) => new pkijs.Certificate({ schema }))) return undefined;
	try {
		return { der, key: Buffer.from(der).toString("hex"), x509: new X509Certificate(der) };
	} catch {
		return undefined;
	}
}

const byDer = (a: Read, b: Read) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

/** The chain chosen: the leaf, its intermediates and one anchor; or why none was. */
export type Chosen =
	| { readonly kind: "chain"; readonly chain: readonly Uint8Array[] }
	| { readonly kind: "malformed" | "path" | "too many intermediates" };

/**
 * The shallowest chain from the leaf to an anchor, breadth first, through what the client sent. An
 * issuer is one node takes as its issuer (`checkIssued`) whose key verifies its signature; none is
 * entered twice, no certificate may have more than 4 of them, no choice looks more than
 * `maxIntermediates` deep (told so where that alone left an issuer out), and a client sends 10, or
 * the intermediates allowed and one more, at most. Among issuers, those sent come first, in the
 * order sent, then the anchors, in DER order.
 */
export function chosen(
	leaf: Uint8Array,
	sent: readonly Uint8Array[],
	anchors: readonly Uint8Array[],
	maxIntermediates: number,
): Chosen {
	if (sent.length > Math.max(most.sent, maxIntermediates + 1)) return { kind: "path" };
	const start = readOf(leaf);
	const offered = sent.map(readOf);
	const trusted = anchors.map(readOf);
	if (!start || offered.some((one) => !one) || trusted.some((one) => !one)) {
		return { kind: "malformed" };
	}
	const fromClient = offered as Read[];
	const fromAnchors = (trusted as Read[]).sort(byDer);
	const anchorKeys = new Set(fromAnchors.map((anchor) => anchor.key));
	const candidates = [
		...new Map([...fromClient, ...fromAnchors].map((one) => [one.key, one])).values(),
	];
	const visited = new Set([start.key]);
	// Whether an issuer was left for lying past the intermediates allowed.
	let cut = false;
	const queue: (readonly Read[])[] = [[start]];
	for (let path = queue.shift(); path; path = queue.shift()) {
		const node = path.at(-1) as Read;
		const issuers = candidates.filter(
			(issuer) => node.x509.checkIssued(issuer.x509) && node.x509.verify(issuer.x509.publicKey),
		);
		if (issuers.length > most.edges) return { kind: "path" };
		for (const issuer of issuers) {
			if (visited.has(issuer.key)) continue;
			if (anchorKeys.has(issuer.key)) {
				return { kind: "chain", chain: [...path, issuer].map((one) => one.der) };
			}
			// The path holds `path.length - 1` intermediates; this one would add another.
			if (path.length > maxIntermediates) {
				cut = true;
				continue;
			}
			visited.add(issuer.key);
			queue.push([...path, issuer]);
		}
	}
	return { kind: cut ? "too many intermediates" : "path" };
}
