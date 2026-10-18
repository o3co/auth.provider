import { deepFreeze, Unavailable } from "@mod/kernel";
import { canonicalAddress } from "@mod/mail";
import { type Contact, type Users, userAttribute } from "./contract.ts";
import { keyOf, none, type UserSource, unanswerable } from "./registered.ts";
import type {
	Changed,
	ContactStore,
	LinkStore,
	RecordStore,
	StoredContacts,
	StoredLink,
} from "./store.ts";

const maxPasswordBytes = 1024;
const maxContacts = 20;

/** A link holds its subject; one removed holds none, and is taken again from what it holds. */
const linkRecord = (subject: string | null) => ({ subject }) as unknown as StoredLink;
/** The subject a record links to, or none when it holds no link. */
const holderOf = (record: StoredLink | undefined) => {
	const subject = (record as { subject?: unknown } | null | undefined)?.subject;
	return typeof subject === "string" ? subject : undefined;
};

const isContact = (item: unknown): item is Contact =>
	(item as Contact | null)?.kind === "email" && typeof (item as Contact).value === "string";
const contactsIn = (record: StoredContacts | undefined): Contact[] =>
	(Array.isArray(record) ? record : [])
		.filter(isContact)
		.map(({ kind, value }) => ({ kind, value }));
const contactsRecord = (contacts: readonly Contact[]) => contacts as unknown as StoredContacts;

function required(...parts: string[]) {
	if (parts.some((part) => part === "")) throw new TypeError("users: an empty part names no one");
}

/** Changes the record, or saves `first` where there is none; one saved meanwhile is changed from what it holds. */
async function written<T>(
	store: RecordStore<T>,
	key: string,
	first: T,
	change: (record: T) => Changed<T> | undefined,
): Promise<{ readonly before: T | undefined; readonly after: T }> {
	const changed = await store.update(key, change);
	if (changed) return changed;
	if ((await store.save(key, first)) === "created") return { before: undefined, after: first };
	const again = await store.update(key, change);
	// The key held a record a moment ago, and records never end.
	if (!again) throw new Unavailable("users");
	return again;
}

/** The source's users, with the links and contacts written through the store interfaces. */
export function ledgerUsers(source: UserSource, links: LinkStore, contacts: ContactStore): Users {
	return {
		verify: async (identifier, password) =>
			// The length is the sender's choice, so answering early tells nothing about users.
			Buffer.byteLength(password) > maxPasswordBytes ? none : source.verify(identifier, password),
		bySubject: source.bySubject,
		byUpstream: async (idp, upstreamSubject) => {
			const fixed = await source.byUpstream(idp, upstreamSubject);
			if (fixed.kind === "user") return fixed;
			const subject = holderOf(await links.read(keyOf({ idp, subject: upstreamSubject })));
			if (subject === undefined) return none;
			const found = await source.bySubject(subject);
			if (found.kind !== "unanswerable") return found;
			return { kind: "user", user: deepFreeze({ subject, attributes: {} }) };
		},
		link: async (subject, upstream) => {
			required(subject, upstream.idp, upstream.subject);
			const fixed = await source.byUpstream(upstream.idp, upstream.subject);
			if (fixed.kind === "user") return fixed.user.subject === subject ? "already" : "conflict";
			const take = (record: StoredLink) =>
				holderOf(record) === undefined ? { value: linkRecord(subject) } : undefined;
			const { before, after } = await written(links, keyOf(upstream), linkRecord(subject), take);
			if (holderOf(after) !== subject) return "conflict";
			return holderOf(before) === subject ? "already" : "linked";
		},
		unlink: async (subject, upstream) => {
			const fixed = await source.byUpstream(upstream.idp, upstream.subject);
			if (fixed.kind === "user") return fixed.user.subject === subject ? "fixed" : "none";
			const release = (record: StoredLink) =>
				holderOf(record) === subject ? { value: linkRecord(null) } : undefined;
			const changed = await links.update(keyOf(upstream), release);
			return changed && holderOf(changed.before) === subject ? "unlinked" : "none";
		},
		verifiedContact: async (subject, contact) => {
			required(subject, contact.value);
			if (contact.kind !== "email") throw new TypeError("users: an unknown kind of contact");
			const kept = { kind: contact.kind, value: contact.value };
			// Compared in mail's one form, the domain's case aside; kept as first given.
			const sameAs = (value: string) => canonicalAddress(value) ?? value;
			const holds = (held: Contact[]) =>
				held.some((c) => c.kind === kept.kind && sameAs(c.value) === sameAs(kept.value));
			const add = (record: StoredContacts) => {
				const held = contactsIn(record);
				if (holds(held) || held.length >= maxContacts) return undefined;
				return { value: contactsRecord([...held, kept]) };
			};
			const { after } = await written(contacts, subject, contactsRecord([kept]), add);
			if (!holds(contactsIn(after))) {
				throw new RangeError(`users: a subject keeps at most ${maxContacts} contacts`);
			}
		},
		contactsOf: async (subject) => deepFreeze(contactsIn(await contacts.read(subject))),
		claimedContacts: async (subject) => {
			const found = await source.bySubject(subject);
			if (found.kind === "unanswerable") return unanswerable;
			const email = found.kind === "user" ? found.user.attributes[userAttribute.email] : undefined;
			return deepFreeze(
				typeof email === "string" && email !== "" ? [{ kind: "email", value: email }] : [],
			);
		},
	};
}
