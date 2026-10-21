import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import type {
	Asserted,
	Ceremonies,
	CeremonyRefusal,
	Credential,
	Verification,
} from "../contract.ts";

export interface RelyingParty {
	readonly id: string;
	readonly name: string;
	readonly origins: readonly string[];
	readonly topOrigins: readonly string[];
	readonly timeoutMs: number;
}

/** EdDSA, ES256 and RS256, as COSE names them. */
const algorithms = [-8, -7, -257];

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** The client data as the library decodes it; none when that is not a JSON object. */
function clientDataOf(response: unknown): Readonly<Record<string, unknown>> | undefined {
	const encoded = (response as { response?: { clientDataJSON?: unknown } } | null)?.response
		?.clientDataJSON;
	if (typeof encoded !== "string") return undefined;
	try {
		const data: unknown = decodeClientDataJSON(encoded);
		return typeof data === "object" && data !== null && !Array.isArray(data)
			? (data as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}

/** The challenge a response answers, read as its verification reads it. */
export function challengeOf(response: unknown): string | undefined {
	const challenge = clientDataOf(response)?.challenge;
	return typeof challenge === "string" ? challenge : undefined;
}

/** The library's messages for a refusal, by how they start; any other refusal is `malformed`. */
const refusals: readonly (readonly [string, CeremonyRefusal])[] = [
	["Unexpected public key alg ", "algorithm"],
	["Unexpected registration response origin ", "origin"],
	["Unexpected authentication response origin ", "origin"],
	["Unexpected registration response challenge ", "challenge"],
	["Unexpected authentication response challenge ", "challenge"],
	["Unexpected RP ID hash", "rp"],
	["User verification", "user-verification"],
];
const refusalOf = (error: unknown): CeremonyRefusal =>
	refusals.find(([start]) => error instanceof Error && error.message.startsWith(start))?.[1] ??
	"malformed";

const refused = (reason: CeremonyRefusal) => ({ kind: "refused" as const, reason });

/** Ends the challenge a request kept when it named credentials: the user was known before it. */
const listedMark = ".listed";

/** The library's answer, or the refusal its error names. */
async function libraryAnswer<T extends object>(
	verify: () => Promise<T>,
): Promise<T | CeremonyRefusal> {
	try {
		return await verify();
	} catch (error) {
		return refusalOf(error);
	}
}

// The client's transports, which the library passes on unchecked: a short list of short strings.
const hintOf = (value: unknown): string[] | undefined =>
	Array.isArray(value) &&
	value.length <= 8 &&
	value.every((t) => typeof t === "string" && t.length <= 32)
		? [...value]
		: undefined;

export function ceremoniesFor(
	rp: RelyingParty,
	random: (n: number) => Uint8Array,
	now: () => number,
): Ceremonies {
	const fresh = () => ({ challenge: base64url(random(32)), until: now() + rp.timeoutMs });
	/** Before the library: a challenge past its end or other than the one given, and a frame not listed. */
	const precheck = (
		response: unknown,
		challenge: string,
		until: number | undefined,
	): CeremonyRefusal | undefined => {
		if (until !== undefined && now() >= until) return "challenge";
		const data = clientDataOf(response);
		if (!data) return "malformed";
		if (data.challenge !== challenge) return "challenge";
		// With no page listed, a frame is refused even when the browser names no page.
		if (data.crossOrigin === true && rp.topOrigins.length === 0) return "top-origin";
		if (data.topOrigin === undefined) return undefined;
		const listed = typeof data.topOrigin === "string" && rp.topOrigins.includes(data.topOrigin);
		return data.crossOrigin === true && listed ? undefined : "top-origin";
	};
	const expected = (challenge: string, v: Verification) => ({
		expectedChallenge: challenge,
		expectedOrigin: [...rp.origins],
		expectedRPID: rp.id,
		requireUserVerification: v === "required",
	});
	return {
		creation: (user, exclude, v, asked = {}) => {
			const discoverable = asked.discoverable ?? true;
			const { challenge, until } = fresh();
			const options = {
				rp: { id: rp.id, name: rp.name },
				user: { id: user.handle, name: user.name, displayName: user.name },
				challenge,
				pubKeyCredParams: algorithms.map((alg) => ({ alg, type: "public-key" })),
				timeout: rp.timeoutMs,
				attestation: "none",
				excludeCredentials: exclude.map((id) => ({ id, type: "public-key" })),
				// Passkeys are asked for with no credential listed, which reaches only a discoverable one.
				authenticatorSelection: {
					residentKey: discoverable ? "required" : "discouraged",
					requireResidentKey: discoverable,
					userVerification: v,
				},
			};
			return { options, challenge, until };
		},
		attest: async (response, challenge, handle, v, until) => {
			const early = precheck(response, challenge, until);
			if (early) return refused(early);
			const verified = await libraryAnswer(() =>
				verifyRegistrationResponse({
					// The library checks the shape it reads.
					response: response as Parameters<typeof verifyRegistrationResponse>[0]["response"],
					...expected(challenge, v),
					supportedAlgorithmIDs: algorithms,
				}),
			);
			if (typeof verified === "string") return refused(verified);
			const info = verified.registrationInfo;
			if (!verified.verified || !info) return refused("signature");
			const transports = hintOf(info.credential.transports);
			return {
				kind: "attested",
				credential: {
					id: info.credential.id,
					publicKey: base64url(info.credential.publicKey),
					signCount: info.credential.counter,
					userHandle: handle,
					backupEligible: info.credentialDeviceType === "multiDevice",
					backedUp: info.credentialBackedUp,
					...(transports ? { transports } : {}),
				},
			};
		},
		request: (allow, v) => {
			const { challenge, until } = fresh();
			const options = {
				challenge,
				timeout: rp.timeoutMs,
				rpId: rp.id,
				allowCredentials: allow.map((c) => ({
					id: c.id,
					type: "public-key",
					...(c.transports ? { transports: c.transports } : {}),
				})),
				userVerification: v,
			};
			return { options, challenge: allow.length > 0 ? challenge + listedMark : challenge, until };
		},
		assert: async (response, kept, credential, v, until) => {
			// The kept challenge alone tells whether the request named credentials; any other ending is unread.
			if (!/^[A-Za-z0-9_-]+(\.listed)?$/.test(kept)) return refused("malformed");
			const listed = kept.endsWith(listedMark);
			const challenge = listed ? kept.slice(0, -listedMark.length) : kept;
			const early = precheck(response, challenge, until);
			if (early) return refused(early);
			const answered = response as Parameters<typeof verifyAuthenticationResponse>[0]["response"];
			if (answered.id !== credential.id) return refused("malformed");
			const verified = await libraryAnswer(() =>
				verifyAuthenticationResponse({
					response: answered,
					...expected(challenge, v),
					// The frame was judged above; the library asks for the list to accept one at all.
					...(rp.topOrigins.length > 0 ? { expectedTopOrigin: [...rp.topOrigins] } : {}),
					// 0, so the library never judges the count before the signature; it is judged below.
					credential: {
						id: credential.id,
						publicKey: new Uint8Array(Buffer.from(credential.publicKey, "base64url")),
						counter: 0,
					},
				}),
			);
			if (typeof verified === "string") return refused(verified);
			if (!verified.verified) return refused("signature");
			return afterSignature(
				credential,
				verified.authenticationInfo,
				answered.response.userHandle,
				listed,
			);
		},
	};
}

/** What a verified signature still has to meet: the handle, the backup eligibility, the count. */
function afterSignature(
	credential: Credential,
	info: {
		newCounter: number;
		credentialDeviceType: string;
		credentialBackedUp: boolean;
		userVerified: boolean;
	},
	userHandle: unknown,
	listed: boolean,
): Asserted {
	// None carried passes only where the request named the credentials (WebAuthn §7.2 step 6):
	// one that is not discoverable may carry none, and the user was known before.
	if (userHandle === undefined || userHandle === null) {
		if (!listed) return refused("user-handle");
	} else if (userHandle !== credential.userHandle) {
		return refused("user-handle");
	}
	if ((info.credentialDeviceType === "multiDevice") !== credential.backupEligible) {
		return refused("backup-eligibility");
	}
	// An authenticator that keeps no count answers 0 every time.
	const kept = info.newCounter === 0 && credential.signCount === 0;
	if (!kept && info.newCounter <= credential.signCount) return refused("sign-count");
	return {
		kind: "asserted",
		credential: { ...credential, signCount: info.newCounter, backedUp: info.credentialBackedUp },
		userVerified: info.userVerified,
	};
}
