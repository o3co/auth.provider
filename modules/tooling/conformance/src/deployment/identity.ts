import { createHash } from "node:crypto";

/** What an instance publishes of itself: its issuer and its keys, each as `<kid>#<thumbprint>`; none where it publishes no metadata. */
export type Identity = { readonly issuer: string; readonly keys: readonly string[] } | null;

const asked = (url: string) =>
	fetch(url, { signal: AbortSignal.timeout(5000) }).then(async (r) =>
		r.ok ? ((await r.json()) as Record<string, unknown>) : undefined,
	);

const required: Readonly<Record<string, readonly string[]>> = {
	EC: ["crv", "kty", "x", "y"],
	OKP: ["crv", "kty", "x"],
	RSA: ["e", "kty", "n"],
};

/** A JWK's RFC 7638 thumbprint. */
export function thumbprintOf(jwk: Readonly<Record<string, unknown>>): string {
	const members = required[String(jwk.kty)];
	if (!members) return `unknown-${String(jwk.kty)}`;
	const canonical = `{${members.map((m) => `${JSON.stringify(m)}:${JSON.stringify(jwk[m])}`).join(",")}}`;
	return createHash("sha256").update(canonical).digest("base64url");
}

/** An instance's identity, read straight from it (not through its trace), where `issuer` publishes it. */
export async function identityOf(baseUrl: string, issuer: string): Promise<Identity> {
	const path = new URL(issuer).pathname.replace(/\/$/, "");
	const metadata =
		(await asked(`${baseUrl}${path}/.well-known/openid-configuration`)) ??
		(await asked(`${baseUrl}/.well-known/oauth-authorization-server${path}`));
	if (!metadata || typeof metadata.issuer !== "string") return null;
	const uri = typeof metadata.jwks_uri === "string" ? metadata.jwks_uri : undefined;
	const set = uri ? await asked(`${baseUrl}${new URL(uri).pathname}`) : undefined;
	const keys = Array.isArray(set?.keys)
		? (set.keys as Record<string, unknown>[])
				.map((k) => `${String(k.kid)}#${thumbprintOf(k)}`)
				.sort()
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
