/** How a declared path reaches a request's path, and which of several reaching one comes first. */

/** Each segment's rank from the request path's first: a literal 0, a middle `*` 1, one under a last `*` 2; none when it does not reach. */
function ranks(declared: string, path: string): number[] | undefined {
	const want = declared.split("/");
	const got = path.split("/");
	const under = declared.endsWith("/*");
	const fixed = under ? want.slice(0, -1) : want;
	if (under ? got.length < want.length : got.length !== want.length) return undefined;
	const each = fixed.map((segment, at) => {
		if (segment !== "*") return segment === got[at] ? 0 : undefined;
		return got[at] === "" ? undefined : 1;
	});
	if (each.some((rank) => rank === undefined)) return undefined;
	return [...(each as number[]), ...got.slice(fixed.length).map(() => 2)];
}

/** Whether `a` comes before `b`, both ranks for one path and so of one length. */
const before = (a: readonly number[], b: readonly number[]) => {
	const at = a.findIndex((rank, i) => rank !== b[i]);
	return at >= 0 && (a[at] ?? 0) < (b[at] ?? 0);
};

/** The declared paths that come first for `path`: at the first segment two differ, a literal over a `*`, a middle `*` over a last. */
export function firstReaching(declared: readonly string[], path: string): ReadonlySet<string> {
	let best: number[] | undefined;
	let first = new Set<string>();
	for (const candidate of new Set(declared)) {
		const ranked = ranks(candidate, path);
		if (!ranked) continue;
		if (!best || before(ranked, best)) {
			best = ranked;
			first = new Set([candidate]);
		} else if (!before(best, ranked)) first.add(candidate);
	}
	return first;
}
