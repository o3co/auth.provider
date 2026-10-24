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

/** Values whose very reading throws: a revoked proxy, and one whose get trap throws. */
export function unreadable(): unknown[] {
	const revoked = Proxy.revocable({}, {});
	revoked.revoke();
	const trap = () => {
		throw new Error("unreadable");
	};
	return [revoked.proxy, new Proxy({}, { get: trap })];
}
