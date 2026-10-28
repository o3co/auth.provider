import * as asn1js from "asn1js";
import type * as pkijs from "pkijs";
import { generalName, oid, parsedExtension } from "./der.ts";

const bytesOf = (name: pkijs.GeneralName) =>
	name.value instanceof asn1js.OctetString ? name.value.valueBlock.valueHexView : new Uint8Array();

export const isSelfIssued = (cert: pkijs.Certificate) => cert.issuer.isEqual(cert.subject);

const bare = (dns: string) => dns.toLowerCase().replace(/\.$/, "");

/** Whether a name lies in a subtree: DNS by labels in any case, IP by network; never across kinds. */
function within(name: pkijs.GeneralName, base: pkijs.GeneralName): boolean {
	if (name.type !== base.type) return false;
	if (name.type === generalName.dns) {
		const [n, b] = [bare(String(name.value)), bare(String(base.value))];
		return b.startsWith(".") ? n.endsWith(b) : n === b || n.endsWith(`.${b}`);
	}
	const [address, network] = [bytesOf(name), bytesOf(base)];
	if (network.length !== 2 * address.length) return false;
	return address.every(
		(byte, at) => ((byte ^ (network[at] ?? 0)) & (network[at + address.length] ?? 0)) === 0,
	);
}

/** Whether a subtree's minimum is 0, by its value's bytes, whatever their length: asn1js reads one of 4 bytes or more as 0. */
const isZero = (minimum: number | asn1js.Integer) =>
	typeof minimum === "number"
		? minimum === 0
		: minimum.valueBlock.valueHexView.every((b) => b === 0);

/** A subtree judged here: a DNS name, or an IPv4 or IPv6 network, without a depth limit. */
function judged(subtree: pkijs.GeneralSubtree): boolean {
	if (!isZero(subtree.minimum) || subtree.maximum !== undefined) return false;
	if (subtree.base.type === generalName.dns) return true;
	return subtree.base.type === generalName.ip && [8, 32].includes(bytesOf(subtree.base).length);
}

function allows(constraints: pkijs.NameConstraints, name: pkijs.GeneralName): boolean {
	if (constraints.excludedSubtrees?.some((s) => within(name, s.base))) return false;
	const permitted = constraints.permittedSubtrees?.filter((s) => s.base.type === name.type) ?? [];
	return permitted.length === 0 || permitted.some((s) => within(name, s.base));
}

/**
 * Why a path's names break its name constraints, if they do (RFC 5280 §4.2.1.10): every name of
 * every certificate is held to each CA above it, all of whose permitted subtrees of its kind it must
 * lie in one of, and none of whose excluded subtrees it may lie in; a self-issued CA is not held.
 * Constraints of a kind not judged here refuse the path.
 */
export function nameConstraintsRefusal(path: readonly pkijs.Certificate[]): string | undefined {
	const constraints = path.map((cert) =>
		parsedExtension<pkijs.NameConstraints>(cert, oid.nameConstraints),
	);
	const subtrees = constraints.flatMap((c) => [
		...(c?.permittedSubtrees ?? []),
		...(c?.excludedSubtrees ?? []),
	]);
	if (!subtrees.every(judged)) return "name constraints unsupported";
	for (const [at, cert] of path.entries()) {
		if (at > 0 && isSelfIssued(cert)) continue;
		const names = (parsedExtension<pkijs.AltName>(cert, oid.subjectAltName)?.altNames ?? []).filter(
			(n) => n.type === generalName.dns || n.type === generalName.ip,
		);
		const above = constraints.slice(at + 1);
		if (names.some((name) => above.some((c) => c !== undefined && !allows(c, name)))) {
			return "name constraints";
		}
	}
	return undefined;
}
