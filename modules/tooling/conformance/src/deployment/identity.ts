/** What an instance publishes of itself: its issuer and the ids of the keys it signs with; none where it publishes no metadata. */
export type Identity = { readonly issuer: string; readonly keys: readonly string[] } | null;

const asked = (url: string) =>
	fetch(url, { signal: AbortSignal.timeout(5000) }).then(async (r) =>
		r.ok ? ((await r.json()) as Record<string, unknown>) : undefined,
	);

/** An instance's identity, read straight from it (not through its trace): its metadata's issuer and its key set's ids. */
export async function identityOf(baseUrl: string): Promise<Identity> {
	const metadata =
		(await asked(`${baseUrl}/.well-known/openid-configuration`)) ??
		(await asked(`${baseUrl}/.well-known/oauth-authorization-server`));
	if (!metadata || typeof metadata.issuer !== "string") return null;
	const set = await asked(`${baseUrl}/.well-known/jwks.json`);
	const keys = Array.isArray(set?.keys)
		? (set.keys as { kid?: unknown }[]).map((k) => String(k.kid)).sort()
		: [];
	return { issuer: metadata.issuer, keys };
}

/** How the instances differ from the first: none where they are one deployment, each naming the same issuer and keys. */
export function identityDifferences(identities: readonly Identity[]): string[] {
	const [first] = identities;
	return identities.slice(1).flatMap((identity, k) => {
		const at = k + 1;
		if (first === null || identity === null) {
			if (first === identity) return [];
			return identity === null
				? [`instance ${at} publishes no metadata, instance 0 does`]
				: [`instance ${at} publishes metadata, instance 0 does not`];
		}
		const found: string[] = [];
		if (identity.issuer !== first?.issuer)
			found.push(`instance ${at} names the issuer ${identity.issuer}, instance 0 ${first?.issuer}`);
		if (identity.keys.join() !== first?.keys.join())
			found.push(
				`instance ${at} publishes the keys ${identity.keys.join(", ")}, instance 0 ${first?.keys.join(", ")}`,
			);
		return found;
	});
}
