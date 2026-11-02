import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SuiteStopFailed } from "../suite/suite.ts";

/** The longest a whole plan may take, its setup and its run, before its stops; they run past it by budgets of their own. */
export const planWithinMs = 25 * 60_000;

/** Where a plan keeps its records under the directory named: one of its own, so plans never mix theirs. */
export const artifactsOf = (plan: string, named: string | undefined): string | undefined =>
	named === undefined ? undefined : join(named, plan);

/**
 * A plan's directories: its work, one of its own removed when it ends, and its records, kept, under
 * the directory named or in one of their own.
 */
export async function planDirs(
	plan: string,
	named: string | undefined,
): Promise<{ readonly work: string; readonly artifacts: string }> {
	const work = await mkdtemp(join(tmpdir(), `interop-oidf-${plan}-`));
	const artifacts =
		artifactsOf(plan, named) ?? (await mkdtemp(join(tmpdir(), `interop-oidf-artifacts-${plan}-`)));
	await mkdir(artifacts, { recursive: true });
	return { work, artifacts };
}

/** A stop that keeps its records first and stops however keeping them went, the records' failure told. */
export const keptThenStopped =
	(keep: () => Promise<void>, stop: () => Promise<void>) => async (): Promise<void> => {
		try {
			await keep();
		} finally {
			await stop();
		}
	};

/** Runs every stop, the last pushed first, though some fail; answers each failure, none swallowed. */
export async function stopAll(stops: readonly (() => Promise<unknown>)[]): Promise<unknown[]> {
	const problems: unknown[] = [];
	for (const stop of [...stops].reverse()) {
		await stop().catch((error: unknown) => problems.push(error));
	}
	return problems;
}

/**
 * Removes a plan's work directory where everything it started was stopped; keeps it where a stop
 * failed, the suite's start's own too, for it holds what stops that part. A failed removal joins
 * `problems`.
 */
export async function cleared(work: string, failure: unknown, problems: unknown[]): Promise<void> {
	if (problems.length > 0 || failure instanceof SuiteStopFailed) return;
	await rm(work, { recursive: true, force: true }).catch((e: unknown) => problems.push(e));
}
