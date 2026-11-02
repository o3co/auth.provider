import type { BuildContext } from "@mod/kernel";
import { type Seal, seal as sealContract } from "@mod/seal";
import { z } from "zod";
import type { StoredUpstreamTokens } from "../store.ts";

/** One IdP's tokens for a session, as kept. */
export interface Kept {
	readonly accessToken: string;
	/** Empty when the upstream gave none that is text, so it is no bearer. */
	readonly tokenType: string;
	readonly refreshToken?: string;
	/** Only for the end-session hint; never handed over. */
	readonly idToken?: string;
	/** Epoch ms on `kernel`'s clock; none when the upstream said no end. */
	readonly expiresAt?: number;
	/** When the end was stated (epoch ms); none when it was not a positive number. */
	readonly obtainedAt?: number;
	/** The scope the login gave; a refresh never moves it. */
	readonly granted: readonly string[];
	readonly scope: readonly string[];
}

/** One IdP's sealed tokens, and the version a rewrite must find. */
export interface Entry {
	readonly version: string;
	readonly sealed: string;
}

/** A session's record: its entries by IdP. */
export type Entries = Readonly<Record<string, Entry>>;

const scopeShape = z.array(z.string().min(1)).readonly();
const keptShape = z
	.strictObject({
		accessToken: z.string().min(1),
		tokenType: z.string(),
		refreshToken: z.string().min(1).optional(),
		idToken: z.string().min(1).optional(),
		expiresAt: z.number().int().optional(),
		obtainedAt: z.number().int().optional(),
		granted: scopeShape,
		scope: scopeShape,
	})
	.readonly();
const recordShape = z.strictObject({
	format: z.literal(1),
	idps: z.record(z.string(), z.strictObject({ version: z.string(), sealed: z.string() })),
});

const contextOf = (session: string, idp: string) => `federation-tokens\n${session}\n${idp}`;

/** Seals and opens a session's upstream tokens, and reads and writes the record they are kept in. */
export function vaultWith(seal: Seal) {
	const read = (
		session: string,
		idp: string,
		entry: Entry,
	): { readonly kept: Kept; readonly resealed?: Entry } | undefined => {
		const opened = seal.open(entry.sealed, contextOf(session, idp));
		if (opened.kind !== "opened") return undefined;
		let parsed: unknown;
		try {
			parsed = JSON.parse(opened.plain);
		} catch {
			return undefined;
		}
		const shaped = keptShape.safeParse(parsed);
		if (!shaped.success) return undefined;
		const kept = shaped.data as Kept;
		if (!opened.stale) return { kept };
		const sealed = seal.seal(opened.plain, contextOf(session, idp));
		return { kept, resealed: { version: entry.version, sealed } };
	};
	return {
		/** The record's entries; a record of another shape holds none. */
		entriesOf: (stored: StoredUpstreamTokens | undefined): Entries => {
			const read = recordShape.safeParse(stored);
			return read.success ? read.data.idps : {};
		},
		/** The record that holds these entries. */
		recordOf: (entries: Entries) =>
			({ format: 1, idps: entries }) as unknown as StoredUpstreamTokens,
		/** Opened tokens, or none when they do not open or hold another shape. */
		open: (session: string, idp: string, entry: Entry): Kept | undefined =>
			read(session, idp, entry)?.kept,
		/** Opened tokens with one opening, and the entry sealed again where a past key sealed it; none as `open`. */
		read,
		seal: (session: string, idp: string, kept: Kept, version: string): Entry => ({
			version,
			sealed: seal.seal(JSON.stringify(keptShape.parse(kept)), contextOf(session, idp)),
		}),
	};
}

export type Vault = ReturnType<typeof vaultWith>;

/** What `vaultFrom` takes from the build context. */
export const vaultTakes = [sealContract] as const;

/** The vault, sealing with the composition's seal. */
export async function vaultFrom(c: Pick<BuildContext<unknown>, "get">): Promise<Vault> {
	return vaultWith(await c.get(sealContract));
}
