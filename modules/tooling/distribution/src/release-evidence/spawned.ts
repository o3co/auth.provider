import type { SpawnSyncReturns } from "node:child_process";

export const succeeded = (answer: Pick<SpawnSyncReturns<unknown>, "status" | "error">) =>
	answer.status === 0 && answer.error === undefined;
