import { X509Certificate } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { decoded, oid, parsedExtension } from "../der.ts";

/** The most certificates a peer may send, issuers one certificate may have, and certificates one choice looks at. */
const most = { sent: 10, edges: 4, looked: 32 } as const;

/** A certificate as a choice reads it: its DER and key, node's reading, and what an issuer is found by. */
interface Read {
	readonly der: Uint8Array;
	readonly key: string;
	readonly x509: X509Certificate;
	readonly subject: string;
	readonly issuer: string;
	readonly ski?: string;
	readonly aki?: string;
}

const hex = (bytes: Uint8Array | ArrayBuffer) => Buffer.from(new Uint8Array(bytes)).toString("hex");

/** A certificate read; none for anything that is not one, as node and pkijs both read it. */
function readOf(der: Uint8Array): Read | undefined {
	const cert = decoded(der, (schema) => new pkijs.Certificate({ schema }));
	if (!cert) return undefined;
	let x509: X509Certificate;
	try {
		x509 = new X509Certificate(der);
	} catch {
		return undefined;
	}
	const ski = parsedExtension<asn1js.OctetString>(cert, oid.subjectKeyIdentifier);
	const aki = parsedExtension<pkijs.AuthorityKeyIdentifier>(cert, oid.authorityKeyIdentifier);
	return {
		der,
		key: hex(der),
		x509,
		// The names as written, byte for byte: what an issuer is indexed and found by.
		subject: hex(cert.subject.toSchema().toBER(false)),
		issuer: hex(cert.issuer.toSchema().toBER(false)),
		...(ski instanceof asn1js.OctetString ? { ski: hex(ski.valueBlock.valueHexView) } : {}),
		...(aki?.keyIdentifier ? { aki: hex(aki.keyIdentifier.valueBlock.valueHexView) } : {}),
	};
}

declare const trusted: unique symbol;
/** The anchors and intermediates a caller trusts, read once; only `choice` reads it. */
export type Trust = { readonly [trusted]: true };

/** What a trust holds: its anchors' keys, and every certificate indexed by key identifier and subject. */
interface Held {
	readonly anchors: ReadonlySet<string>;
	readonly bySki: ReadonlyMap<string, readonly Read[]>;
	readonly bySubject: ReadonlyMap<string, readonly Read[]>;
}

const indexed = (all: readonly Read[], keyOf: (read: Read) => string | undefined) => {
	const index = new Map<string, Read[]>();
	for (const read of all) {
		const key = keyOf(read);
		if (key !== undefined) index.set(key, [...(index.get(key) ?? []), read]);
	}
	return index;
};

/**
 * The trust a path is chosen within: the anchors, and intermediates a peer may leave out. Every one
 * must be a certificate, and, with `selfSignedAnchorsOnly`, every anchor self-signed; else TypeError.
 */
export function trustOf(given: {
	readonly anchors: readonly Uint8Array[];
	readonly intermediates?: readonly Uint8Array[];
	readonly selfSignedAnchorsOnly: boolean;
}): Trust {
	const read = (der: Uint8Array) => {
		const one = readOf(der);
		if (!one) throw new TypeError("a trusted certificate that is not one");
		return one;
	};
	const anchors = given.anchors.map(read);
	if (given.selfSignedAnchorsOnly) {
		for (const anchor of anchors) {
			if (!anchor.x509.checkIssued(anchor.x509) || !anchor.x509.verify(anchor.x509.publicKey)) {
				throw new TypeError("an anchor that is not self-signed");
			}
		}
	}
	// In DER order, so a choice among them is always the same.
	const all = [...anchors, ...(given.intermediates ?? []).map(read)].sort((a, b) =>
		a.key < b.key ? -1 : a.key > b.key ? 1 : 0,
	);
	const held: Held = Object.freeze({
		anchors: new Set(anchors.map((anchor) => anchor.key)),
		bySki: indexed(all, (one) => one.ski),
		bySubject: indexed(all, (one) => one.subject),
	});
	return held as unknown as Trust;
}

/** The chain chosen: the leaf, its intermediates and one anchor; or why none was. */
export type Chosen =
	| { readonly kind: "chain"; readonly chain: readonly Uint8Array[] }
	| { readonly kind: "malformed" | "path" | "too many intermediates" };

/**
 * The shallowest chain from the leaf to an anchor, breadth first, through what the peer sent and the
 * trust's certificates. An issuer is one node takes as its issuer (`checkIssued`) whose key verifies
 * its signature; none is entered twice, no certificate may have more than 4 of them, no choice looks at
 * more than 32 certificates or more than `maxIntermediates` deep (told so where that alone left an
 * issuer out), and a peer sends 10 at most. Among
 * issuers, those sent come first, in the order sent, then the trust's, in DER order.
 */
export function chosen(
	leaf: Uint8Array,
	sent: readonly Uint8Array[],
	given: Trust,
	maxIntermediates: number,
): Chosen {
	const trust = given as unknown as Held;
	if (sent.length > most.sent) return { kind: "path" };
	const start = readOf(leaf);
	const offered = sent.map(readOf);
	if (!start || offered.some((one) => one === undefined)) return { kind: "malformed" };
	const fromPeer = offered as Read[];
	const candidatesOf = (node: Read) => {
		const seen = new Set<string>();
		const keep = (one: Read) => {
			if (seen.has(one.key)) return false;
			seen.add(one.key);
			return true;
		};
		const fromTrust = [
			...(node.aki ? (trust.bySki.get(node.aki) ?? []) : []),
			...(trust.bySubject.get(node.issuer) ?? []),
		].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
		return [...fromPeer.filter(keep), ...fromTrust.filter(keep)];
	};
	const visited = new Set([start.key]);
	// Whether an issuer was left for lying past the intermediates allowed.
	let cut = false;
	const queue: (readonly Read[])[] = [[start]];
	for (let path = queue.shift(); path; path = queue.shift()) {
		const node = path.at(-1) as Read;
		const issuers = candidatesOf(node).filter(
			(issuer) => node.x509.checkIssued(issuer.x509) && node.x509.verify(issuer.x509.publicKey),
		);
		if (issuers.length > most.edges) return { kind: "path" };
		for (const issuer of issuers) {
			if (visited.has(issuer.key)) continue;
			if (trust.anchors.has(issuer.key)) {
				return { kind: "chain", chain: [...path, issuer].map((one) => one.der) };
			}
			// The path holds `path.length - 1` intermediates; this one would add another.
			if (path.length > maxIntermediates) {
				cut = true;
				continue;
			}
			visited.add(issuer.key);
			if (visited.size > most.looked) return { kind: "path" };
			queue.push([...path, issuer]);
		}
	}
	return { kind: cut ? "too many intermediates" : "path" };
}
