import type { Keys } from "@mod/keys";
import type { Hint, IdTokenHints } from "./contract.ts";

const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.length > 0;

/** The client the token was issued to: `azp` when the audience names it, else the one audience. */
const clientOf = (aud: unknown, azp: unknown): string | undefined => {
	const audience = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud : [];
	if (nonEmpty(azp) && audience.includes(azp)) return azp;
	const [only] = audience;
	return audience.length === 1 && nonEmpty(only) ? only : undefined;
};

export function hintsOver(p: { keys: Keys; issuer: string }): IdTokenHints {
	return {
		check: async (token): Promise<Hint> => {
			const verified = await p.keys.verify(token, "JWT");
			if (verified.kind !== "valid") return { kind: "invalid" };
			const { iss, sub, iat, exp, sid, aud, azp } = verified.claims;
			if (iss !== p.issuer || !nonEmpty(sub)) return { kind: "invalid" };
			if (typeof iat !== "number" || typeof exp !== "number") return { kind: "invalid" };
			if (!nonEmpty(sid)) return { kind: "sessionless" };
			const client = clientOf(aud, azp);
			const issuedAt = iat * 1000;
			return { kind: "valid", subject: sub, session: sid, issuedAt, ...(client ? { client } : {}) };
		},
	};
}
