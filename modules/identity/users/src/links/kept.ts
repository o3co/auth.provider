import { Unavailable } from "@mod/kernel";
import type { Linking } from "../ledger.ts";
import { keyOf, none, type UserSource } from "../registered.ts";
import { type LinkStore, type StoredLink, written } from "../store.ts";

/** A link holds its subject; one removed holds none, and is taken again from what it holds. */
const linkRecord = (subject: string | null) => ({ subject }) as unknown as StoredLink;
/** The subject a record links to, or none when it holds no link. */
const holderOf = (record: StoredLink | undefined) => {
	const subject = (record as { subject?: unknown } | null | undefined)?.subject;
	return typeof subject === "string" ? subject : undefined;
};

/** Links written through the link store, below the source's own, which win and cannot be unlinked. */
export function keptLinks(source: UserSource, links: LinkStore): Linking {
	return {
		byUpstream: async (idp, upstreamSubject) => {
			const fixed = await source.byUpstream(idp, upstreamSubject);
			if (fixed.kind === "user") return fixed;
			const subject = holderOf(await links.read(keyOf({ idp, subject: upstreamSubject })));
			if (subject === undefined) return none;
			const found = await source.bySubject(subject);
			if (found.kind === "unanswerable") throw new Unavailable("users");
			return found;
		},
		link: async (subject, upstream) => {
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
	};
}
