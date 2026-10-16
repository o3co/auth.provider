import { contract, extensionPoint } from "@mod/kernel";
import { isAddress } from "@mod/mail";

export interface User {
	readonly subject: string;
	/** Read once and frozen. */
	readonly attributes: Readonly<Record<string, unknown>>;
}

/** The names of the attributes users knows: their OIDC claim names, typed below; a user may hold others. */
export const userAttribute = Object.freeze({
	email: "email",
	emailVerified: "email_verified",
	name: "name",
	picture: "picture",
	groups: "groups",
} as const);

export interface UserAttributes {
	readonly [userAttribute.email]?: string;
	readonly [userAttribute.emailVerified]?: boolean;
	readonly [userAttribute.name]?: string;
	readonly [userAttribute.picture]?: string;
	readonly [userAttribute.groups]?: readonly string[];
}

/** Text with no control or format character, bidi controls among them. */
const isPlainText = (value: unknown): value is string =>
	typeof value === "string" && !/[\p{Cc}\p{Cf}]/u.test(value);

/** An https URL that reads back as given: no blank character, and its parsed form unchanged. */
function isPictureUrl(value: unknown): boolean {
	if (!isPlainText(value) || /\s/u.test(value)) return false;
	const url = URL.parse(value);
	return url?.protocol === "https:" && url.href === value;
}

const attributeRules = new Map<string, (value: unknown) => boolean>([
	[userAttribute.email, isAddress],
	[userAttribute.emailVerified, (value) => typeof value === "boolean"],
	[userAttribute.name, isPlainText],
	[userAttribute.picture, isPictureUrl],
	[userAttribute.groups, (value) => Array.isArray(value) && value.every(isPlainText)],
]);

/** Whether `value` is a form users accepts for the attribute `name`; another name takes any value, a string only as plain text. */
export const isAttributeValue = (name: string, value: unknown): boolean =>
	(attributeRules.get(name) ?? ((other) => typeof other !== "string" || isPlainText(other)))(value);

/**
 * From values of any shape, the attributes users names, each in a form it accepts, frozen; an
 * email's verification only beside the email. Any other name or form is left out.
 */
export function acceptedAttributes(values: unknown): UserAttributes {
	if (typeof values !== "object" || values === null || Array.isArray(values))
		return Object.freeze({});
	const given = values as Record<string, unknown>;
	// Each value is read once, and a list copied before it is judged, so what is judged is what is kept.
	const at = (name: string) => {
		const read = given[name];
		const value = Array.isArray(read) ? [...read] : read;
		return isAttributeValue(name, value) ? value : undefined;
	};
	const email = at(userAttribute.email) as string | undefined;
	const verified =
		email === undefined ? undefined : (at(userAttribute.emailVerified) as boolean | undefined);
	const name = at(userAttribute.name) as string | undefined;
	const picture = at(userAttribute.picture) as string | undefined;
	const groups = at(userAttribute.groups) as readonly string[] | undefined;
	return Object.freeze({
		...(email === undefined ? {} : { [userAttribute.email]: email }),
		...(verified === undefined ? {} : { [userAttribute.emailVerified]: verified }),
		...(name === undefined ? {} : { [userAttribute.name]: name }),
		...(picture === undefined ? {} : { [userAttribute.picture]: picture }),
		...(groups === undefined ? {} : { [userAttribute.groups]: Object.freeze(groups) }),
	});
}

/** A subject's shape, as OpenID Connect Core §2 bounds `sub`: 1 to 255 ASCII characters. */
export const isWellFormedSubject = (value: unknown): value is string =>
	typeof value === "string" && /^\p{ASCII}{1,255}$/u.test(value);

export type Verified = { readonly kind: "user"; readonly user: User } | { readonly kind: "none" };
/** What the user ledger answers when it cannot look users up by subject; never read as none. */
export type Unanswerable = { readonly kind: "unanswerable" };
export type BySubject = Verified | Unanswerable;

/** An IdP's name and the upstream subject there. */
export interface UpstreamIdentity {
	readonly idp: string;
	readonly subject: string;
}

export interface Contact {
	readonly kind: "email";
	readonly value: string;
}

export interface Users {
	/** Takes the same work whether or not the user exists; throws Unavailable if the ledger fails. */
	verify(identifier: string, password: string): Promise<Verified>;
	bySubject(subject: string): Promise<BySubject>;
	/** The user an upstream identity is linked to, by the IdP's name and the upstream subject, exactly. */
	byUpstream(idp: string, upstreamSubject: string): Promise<Verified>;
	/** Links the upstream identity to the subject; conflict when it is linked to another. Throws TypeError on an empty part. */
	link(subject: string, upstream: UpstreamIdentity): Promise<"linked" | "already" | "conflict">;
	/** Removes a link written here; fixed when the settings hold it for the subject. */
	unlink(subject: string, upstream: UpstreamIdentity): Promise<"unlinked" | "none" | "fixed">;
	/** Keeps a contact the subject has shown is theirs, up to 20. Throws TypeError on an empty part, RangeError past 20. */
	verifiedContact(subject: string, contact: Contact): Promise<void>;
	/** The subject's verified contacts, in the order first kept, frozen. */
	contactsOf(subject: string): Promise<readonly Contact[]>;
	/** Contacts the settings or the ledger state for the subject, not shown to be theirs; frozen, or unanswerable. */
	claimedContacts(subject: string): Promise<readonly Contact[] | Unanswerable>;
}

export interface Ledger {
	/** None when no user matches, after the same work as for a known identifier; throws Unavailable when the ledger fails or refuses. */
	verify(identifier: string, password: string): Promise<Verified>;
	bySubject(subject: string): Promise<BySubject>;
}

export const users = contract<Users>("users");
export const ledgers = extensionPoint<Ledger>("users.ledgers", { multiplicity: "many" });
export * from "./store.ts";
