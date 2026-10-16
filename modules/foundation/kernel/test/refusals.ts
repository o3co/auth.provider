import { BootRefused, type Refusal } from "../src/contract.ts";

/** The refusals `run` is refused with; any other outcome fails the test. */
export async function refusalsOf(run: Promise<unknown>): Promise<readonly Refusal[]> {
	try {
		await run;
	} catch (error) {
		if (error instanceof BootRefused) return error.refusals;
		throw error;
	}
	throw new Error("expected a refusal");
}
