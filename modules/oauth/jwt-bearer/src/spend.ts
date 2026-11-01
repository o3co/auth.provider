import { isUnavailable, Unavailable } from "@mod/kernel";

/**
 * Uses an assertion up at a boundary, its issuer's ledger or its delegate, read there: any throw is
 * Unavailable, and so is an answer that is not one of `accepted`.
 */
export async function spentAt<A extends string>(
	spend: () => Promise<unknown>,
	accepted: readonly A[],
): Promise<A> {
	let told: unknown;
	try {
		told = await spend();
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("jwt-bearer");
	}
	if (!(accepted as readonly unknown[]).includes(told)) throw new Unavailable("jwt-bearer");
	return told as A;
}
