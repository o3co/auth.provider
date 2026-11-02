import { onNew } from "@mod/conformance";
import { type KeysPart, keysArea } from "./area.ts";

function keysSection(part: KeysPart): Record<string, unknown> {
	const s = part.signing;
	const section: Record<string, unknown> = {};
	if (s) {
		section.signing =
			s.alg === "HS256"
				? { kid: s.kid, alg: s.alg, secret: s.secretHex }
				: { kid: s.kid, alg: s.alg, "private-key": s.privatePem };
	}
	if (part.previous) {
		section.previous = part.previous.map((p) => ({
			kid: p.kid,
			alg: p.alg,
			"public-key": p.publicPem,
			"expires-at": p.expiresAt,
		}));
	}
	if (part.unknownSetting) section["not-a-setting"] = 1;
	return section;
}

/**
 * oidc signs ID tokens with RS256 unless the operator writes another: a scene signing with another
 * key writes it, as that operator would, where oidc is composed.
 */
const idTokenAlg = (part: KeysPart, modules: readonly string[]) => {
	const alg = part.signing?.alg;
	return alg === undefined || alg === "HS256" || alg === "RS256" || !modules.includes("@mod/oidc")
		? {}
		: { oidc: { "id-token-alg": alg } };
};

// The keys a scene sets are the deployment's only ones: a pattern's app mixes none of its own in.
onNew(keysArea, (part, _scene, modules) => ({
	modules: ["@mod/keys"],
	whole: ["keys"],
	config: { keys: keysSection(part), ...idTokenAlg(part, modules) },
	// ID tokens need an asymmetric key, so a deployment signing only with a shared secret has no oidc.
	...(part.signing?.alg === "HS256" ? { without: ["@mod/oidc"] } : {}),
}));
