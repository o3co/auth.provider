/**
 * Whether the image's Node is behind a security release of its major, read from Node's release
 * index; Trivy does not see the Node runtime in Node's official images. An index that cannot be
 * fetched or read, or that does not list the image's Node, is not checked, never passed.
 */

export const nodeIndex = "https://nodejs.org/dist/index.json";

export type NodeChecked =
	| { readonly behind: false; readonly version: string }
	| {
			readonly behind: true;
			readonly version: string;
			readonly newest: string;
			/** The minor the image's Node must move to, `<major>.<minor>`. */
			readonly minor: string;
	  }
	| { readonly notChecked: string };

const parsed = (v: string) => {
	const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(v);
	return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
};
const newer = (a: readonly number[], b: readonly number[]) =>
	a[0] !== b[0]
		? (a[0] ?? 0) > (b[0] ?? 0)
		: a[1] !== b[1]
			? (a[1] ?? 0) > (b[1] ?? 0)
			: (a[2] ?? 0) > (b[2] ?? 0);

/** `version` as `node -p process.version` wrote it; `index` Node's release index as text. */
export async function nodeChecked(
	version: string,
	index: () => Promise<string>,
): Promise<NodeChecked> {
	const own = version.trim();
	const at = parsed(own);
	if (!at) return { notChecked: `the image's Node version is not one: ${own}` };
	let releases: unknown;
	try {
		releases = JSON.parse(await index());
	} catch (error) {
		return {
			notChecked: `Node's release index could not be read: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const formed =
		Array.isArray(releases) &&
		releases.every(
			(r) =>
				typeof r === "object" &&
				r !== null &&
				typeof (r as { version?: unknown }).version === "string" &&
				typeof ((r as { security?: unknown }).security ?? false) === "boolean",
		);
	if (!formed) return { notChecked: "Node's release index is not its form" };
	const listed = releases as readonly { readonly version: string; readonly security?: boolean }[];
	if (!listed.some((r) => r.version === own))
		return { notChecked: `Node's release index does not list ${own}` };
	const ahead = listed
		.map((r) => ({ release: r, at: parsed(r.version) }))
		.filter((r) => r.release.security === true && r.at && r.at[0] === at[0] && newer(r.at, at))
		.toSorted((a, b) => (newer(a.at ?? [], b.at ?? []) ? -1 : 1));
	const newest = ahead[0];
	if (!newest?.at) return { behind: false, version: own };
	return {
		behind: true,
		version: own,
		newest: newest.release.version,
		minor: `${newest.at[0]}.${newest.at[1]}`,
	};
}

/** Node's release index as text, within a time; a status other than 200 fails. */
export async function fetchNodeIndex(): Promise<string> {
	const answer = await fetch(nodeIndex, { signal: AbortSignal.timeout(30_000) });
	if (!answer.ok) throw new Error(`${nodeIndex} answered ${answer.status}`);
	return answer.text();
}
