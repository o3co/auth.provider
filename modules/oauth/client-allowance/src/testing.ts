import { type Allowances, allowances } from "./metadata.ts";

/** A test client's sections holding these allowances. */
export function allowancesFor(settings: Partial<Allowances>) {
	return { [allowances.name]: settings };
}
