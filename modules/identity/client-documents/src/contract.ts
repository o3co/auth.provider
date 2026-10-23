import type { Section } from "@mod/clients";
import { extensionPoint } from "@mod/kernel";

/** Where a client's metadata document came from: its client id, and the host its source checked. */
export interface DocumentSource {
	readonly id: string;
	readonly host: string;
}

/**
 * A section's value from a document, before the section's schema checks it; `refused` names the
 * field (RFC 7591's word) that refuses the client, never its text; nothing when the section takes
 * nothing from this document.
 */
export type Copied = { readonly value: unknown } | { readonly refused: string } | undefined;

/** How the owner of a `clients` section fills it from a client's metadata document. */
export interface DocumentCopy {
	/** The section the copy fills. */
	readonly section: Section<unknown>;
	/** The document's fields (RFC 7591's words) `copy` reads. */
	readonly reads: readonly string[];
	/**
	 * The section's value from the document. It holds the section's own keys alone, never the
	 * document's, so where a check fails holds no document text. A section that widens what a client
	 * may do takes from a document only what a document may say.
	 */
	copy(document: Readonly<Record<string, unknown>>, from: DocumentSource): Copied;
}

/** The copies, one per section, by the section's name. */
export const documentCopies = extensionPoint<DocumentCopy>("client-documents.copies", {
	multiplicity: "keyed",
	keyOf: (copy) => copy.section.name,
});
