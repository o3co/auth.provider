import type { ContactStore, LinkStore } from "../store.ts";

/**
 * Why a link and a contact store's ports cannot be used together, or none. The one statement of the
 * sets: the link store's `issuers` and `unowned` come together or neither; its `remove`, `erase` and
 * `migrate` come together or none, and only with `issuers`; the contact store's `erase` and
 * `migrate` together or neither. A part of a set would leave records users cannot find, erase or
 * tell apart.
 */
export function portsRefused(links: LinkStore, contacts: ContactStore): string | undefined {
	if ((links.issuers === undefined) !== (links.unowned === undefined)) {
		return "the link store offers one of issuers and unowned: it offers both, for names to leave the link space, or neither";
	}
	const linkPorts = [links.remove, links.erase, links.migrate].filter((p) => p !== undefined);
	if (linkPorts.length !== 0 && linkPorts.length !== 3) {
		return "the link store offers part of remove, erase and migrate: it offers all three, or none";
	}
	if (linkPorts.length === 3 && links.issuers === undefined) {
		return "the link store offers erase and migrate without issuers: names would stay in the link space";
	}
	if ((contacts.erase === undefined) !== (contacts.migrate === undefined)) {
		return "the contact store offers one of erase and migrate: it offers both, or neither";
	}
	return undefined;
}

/** Whether the stores offer every set whole, as users' eraser needs to erase: none refused, none missing. */
export const everyPortOffered = (links: LinkStore, contacts: ContactStore): boolean =>
	portsRefused(links, contacts) === undefined &&
	links.erase !== undefined &&
	links.issuers !== undefined &&
	contacts.erase !== undefined;
