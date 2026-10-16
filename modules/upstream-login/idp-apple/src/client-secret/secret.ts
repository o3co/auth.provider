import type { KeyObject } from "node:crypto";
import { SignJWT } from "jose";

export interface SecretParts {
	readonly teamId: string;
	readonly keyId: string;
	readonly clientId: string;
	/** The team's P-256 key. */
	readonly key: KeyObject;
	readonly lifetimeMs: number;
	/** Apple's issuer. */
	readonly audience: string;
}

/** Apple's client secret: a JWT the team's key signs, made again once half its life is spent. */
export function secretOf(parts: SecretParts, clock: { now(): number }) {
	let held:
		| { readonly jwt: Promise<string>; readonly madeAt: number; readonly key: KeyObject }
		| undefined;
	const signed = (madeAt: number, key: KeyObject) => {
		const iat = Math.floor(madeAt / 1000);
		return new SignJWT({})
			.setProtectedHeader({ alg: "ES256", kid: parts.keyId })
			.setIssuer(parts.teamId)
			.setSubject(parts.clientId)
			.setAudience(parts.audience)
			.setIssuedAt(iat)
			.setExpirationTime(iat + Math.floor(parts.lifetimeMs / 1000))
			.sign(key);
	};
	return {
		/** The secret to send now; requests at once share one signing. */
		current(): Promise<string> {
			const [now, key] = [clock.now(), parts.key];
			// A held secret serves only the key that made it.
			if (held?.key === key && now - held.madeAt < parts.lifetimeMs / 2) return held.jwt;
			const made = { jwt: signed(now, key), madeAt: now, key };
			held = made;
			// A signing that failed is not kept, so the next request signs again.
			made.jwt.catch(() => {
				if (held === made) held = undefined;
			});
			return made.jwt;
		},
	};
}
