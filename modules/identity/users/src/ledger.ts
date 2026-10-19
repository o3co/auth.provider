import { deepFreeze } from "@mod/kernel";
import { canonicalAddress } from "@mod/mail";
import { type Contact, isWellFormedSubject, type Users, userAttribute } from "./contract.ts";
import { none, type UserSource, unanswerable } from "./registered.ts";
import { type ContactStore, type StoredContacts, written } from "./store.ts";

const maxPasswordBytes = 1024;
const maxContacts = 20;

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

/** Who answers by upstream identity and keeps links: users through its link store, or the ledger. */
export type Linking = Pick<Users, "byUpstream" | "link" | "unlink">;

/** The source's users, linked as `linking` links them, with the contacts written through the store interface. */
export function ledgerUsers(source: UserSource, linking: Linking, contacts: ContactStore): Users {
	return {
		verify: async (identifier, password) =>
			// The length is the sender's choice, so answering early tells nothing about users.
			Buffer.byteLength(password) > maxPasswordBytes ? none : source.verify(identifier, password),
		bySubject: source.bySubject,
		byUpstream: linking.byUpstream,
		link: async (subject, upstream) => {
			required(subject, upstream.idp, upstream.subject);
			if (!isWellFormedSubject(subject))
				throw new TypeError("users: a subject is 1 to 255 ASCII characters");
			return linking.link(subject, upstream);
		},
		unlink: linking.unlink,
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
