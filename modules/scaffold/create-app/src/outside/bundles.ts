/**
 * Each bundle's dependencies on other bundles, as `distribution` derives them: where its members'
 * runtime dependencies lie. The index holds each member's manifest and bundle, so it tells them.
 */
export function bundlesIn(
	members: readonly {
		readonly name: string;
		readonly package: string;
		readonly manifest?: Readonly<Record<string, unknown>>;
	}[],
): Record<string, string[]> {
	const bundleOf = new Map(members.map((member) => [member.name, member.package]));
	const depended = new Map<string, Set<string>>();
	for (const member of members) {
		for (const name of Object.keys(member.manifest?.dependencies ?? {})) {
			const other = bundleOf.get(name);
			if (other === undefined || other === member.package) continue;
			depended.set(member.package, (depended.get(member.package) ?? new Set()).add(other));
		}
	}
	return Object.fromEntries([...depended].map(([bundle, others]) => [bundle, [...others]]));
}
