import { isUnavailable, Unavailable } from "@mod/kernel";
import type { JtiLedger, SpendingAssertion } from "./contract.ts";

/**
 * Uses an assertion up in its issuer's ledger, read at this boundary: any throw is Unavailable, and
 * so is an answer that is neither `first` nor `replayed`.
 */
export async function spentIn(
	ledger: JtiLedger,
	assertion: SpendingAssertion,
): Promise<"first" | "replayed"> {
	let told: unknown;
	try {
		told = await ledger.spend(assertion);
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("jwt-bearer");
	}
	if (told !== "first" && told !== "replayed") throw new Unavailable("jwt-bearer");
	return told;
}
