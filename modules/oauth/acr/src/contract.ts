import { contract, extensionPoint } from "@mod/kernel";
import { z } from "zod";

/** The amr sets that meet an acr: a session holding all of any one set meets it. */
export type AmrSets = readonly (readonly string[])[];

/** The one rule for amr sets, the operator's and the offered alike: non-empty sets in a non-empty list. */
export const amrSetsShape = z.array(z.array(z.string()).min(1)).min(1);

export const isAmrSets = (sets: unknown): sets is AmrSets => amrSetsShape.safeParse(sets).success;

/** An acr the deployment offers by itself; the operator's table wins for the same acr. */
export interface AcrEntry {
	readonly acr: string;
	readonly sets: AmrSets;
}

export const acrEntries = extensionPoint<AcrEntry>("acr.entries", {
	multiplicity: "keyed",
	keyOf: (entry) => entry.acr,
});

/** Decisions on the acr a request asks for; the table stays here. */
export interface Acr {
	/** The acr the table knows among `asked`, the request's space-separated acr_values, in the order asked. */
	known(asked: string): readonly string[];
	/** The first of these acr the amr meet, if any. */
	met(known: readonly string[], amr: readonly string[]): string | undefined;
}

export const acr = contract<Acr>("acr");
