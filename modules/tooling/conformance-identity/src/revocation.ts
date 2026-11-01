/**
 * How long after the ledger's revocation of a subject answered a login of that subject may still be
 * refused: the window U-0.19-126 states (a boundary is its write's deadline, compared in seconds), with a
 * margin for the clocks it is read on.
 */
export const revocationWindowMs = 11_100;

/**
 * Until a login is a second and more past the latest of these recorded boundaries (epoch ms, compared in
 * seconds), with a margin for the clocks they are recorded and compared on. None given is an error.
 */
export async function pastBoundaries(recorded: readonly number[]) {
	if (recorded.length === 0) throw new Error("no boundary recorded to wait past");
	const wait = (Math.floor(Math.max(...recorded) / 1000) + 1) * 1000 + 100 - Date.now();
	if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
}
