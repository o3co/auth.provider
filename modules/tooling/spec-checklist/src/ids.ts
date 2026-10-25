/** An item's ID: its spec, its section in the spec, and its letter within the section. */
export const itemId =
	/^(rfc\d{4}|oidc-(?:core|discovery|rpinit|bcl))-((?:\d+|[A-Z])(?:\.\d+)*)-([a-z]{1,2})$/;

/** Anything written like an item ID, well formed or not, so that none goes unseen. */
export const idLike =
	/(?<![\w-])(?:rfc\d{4}|oidc-(?:core|discovery|rpinit|bcl))-[0-9A-Za-z.]+-[a-z]{1,2}(?![\w-])/g;

export type Strength = "MUST" | "MUST NOT" | "SHOULD" | "SHOULD NOT";

/** The requirement keywords a ledger counts, the longer phrase first. */
export const keywords = [
	"MUST NOT",
	"MUST",
	"REQUIRED",
	"SHALL NOT",
	"SHALL",
	"SHOULD NOT",
	"SHOULD",
	"NOT RECOMMENDED",
	"RECOMMENDED",
] as const;
export type Keyword = (typeof keywords)[number];

/** Whether a keyword or strength binds as a MUST does, or as a SHOULD does. */
export const classOf = (word: Keyword | Strength): "MUST" | "SHOULD" =>
	word.startsWith("MUST") || word.startsWith("SHALL") || word === "REQUIRED" ? "MUST" : "SHOULD";

export const specOf = (id: string) => itemId.exec(id)?.[1];
