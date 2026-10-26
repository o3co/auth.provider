import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ModuleRun } from "../results/results.ts";

/** A page the suite's browser kept for a person to review, with what the suite asks of it. */
export interface ReviewPage {
	/** The file it is kept in, named by its test. */
	readonly file: string;
	readonly test: string;
	readonly instance?: string;
	/** The suite's condition that asks for the review. */
	readonly condition?: string;
	/** What the suite asks the page to show. */
	readonly asks?: string;
	/** The text the harness's browser waited for before keeping the page. */
	readonly matched?: string;
	readonly contentType?: string;
	/** The page as the browser held it; none where the suite kept none. */
	readonly page?: string;
}

/** The fields of a review entry the suite's log holds beyond the ones the results read. */
interface ReviewEntry {
	readonly result?: string;
	readonly src?: string;
	readonly msg?: string;
	readonly page_source?: string;
	readonly content_type?: string;
	readonly matched_regexp?: string;
}

/**
 * The pages of each test the suite left for a person's review, one per review entry of its log, in
 * the order the tests ran: the page its browser kept in the entry, or none. Each is named by its
 * test, a second of the same name numbered.
 */
export function reviewPages(runs: readonly ModuleRun[]): ReviewPage[] {
	const named = new Map<string, number>();
	return runs
		.filter((run) => run.info?.result === "REVIEW")
		.flatMap((run) =>
			(run.log as readonly ReviewEntry[])
				.filter((e) => e.result === "REVIEW")
				.map((e) => {
					const n = (named.get(run.testModule) ?? 0) + 1;
					named.set(run.testModule, n);
					return {
						file: `${run.testModule}${n === 1 ? "" : `-${n}`}.html`,
						test: run.testModule,
						...(run.instance === undefined ? {} : { instance: run.instance }),
						...(e.src === undefined ? {} : { condition: e.src }),
						...(e.msg === undefined ? {} : { asks: e.msg }),
						...(e.matched_regexp === undefined ? {} : { matched: e.matched_regexp }),
						...(e.content_type === undefined ? {} : { contentType: e.content_type }),
						...(e.page_source === undefined ? {} : { page: e.page_source }),
					};
				}),
		);
}

/**
 * Keeps in `dir` each review page as a file of its own, and `index.json`: every review entry in
 * order, what the suite asks of it and the page's file (none where the suite kept no page). Makes
 * nothing where no test was left for review.
 */
export async function keepReviewPages(dir: string, runs: readonly ModuleRun[]): Promise<void> {
	const pages = reviewPages(runs);
	if (pages.length === 0) return;
	await mkdir(dir, { recursive: true });
	for (const p of pages) if (p.page !== undefined) await writeFile(join(dir, p.file), p.page);
	const index = pages.map(({ page, ...rest }) => ({
		...rest,
		file: page === undefined ? null : rest.file,
	}));
	await writeFile(join(dir, "index.json"), `${JSON.stringify(index, null, 2)}\n`);
}
