import type { ContactStore, LinkStore } from "../store.ts";

/**
 * Why a link and a contact store's ports cannot be used together, or none: `remove`, `erase` and
 * `migrate` come as one set on the link store, with `names`, and `erase` and `migrate` together on
 * the contact store; a part of a set would leave records users cannot find, erase or tell apart.
 */
export function portsRefused(links: LinkStore, contacts: ContactStore): string | undefined {
	const linkPorts = [links.remove, links.erase, links.migrate].filter((p) => p !== undefined);
	if (linkPorts.length !== 0 && linkPorts.length !== 3) {
		return "the link store offers part of remove, erase and migrate: it offers all three, or none";
	}
	if (linkPorts.length === 3 && links.names === undefined) {
		return "the link store offers erase and migrate without names: names would stay in the link space";
	}
	if ((contacts.erase === undefined) !== (contacts.migrate === undefined)) {
		return "the contact store offers one of erase and migrate: it offers both, or neither";
	}
	return undefined;
}
