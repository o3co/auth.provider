import { Unavailable } from "@mod/kernel";
import type { FactorKind, Opened, Verified } from "@mod/mfa-extensions";
import type { SubjectAttributes } from "@mod/subject-attributes";
import { userAttribute } from "@mod/users";
import {
	type Ceremonies,
	type Credential,
	credentialOf,
	freshHandle,
	type Verification,
} from "@mod/webauthn";
import { z } from "zod";
import { showable } from "./name.ts";

/** RFC 8176: a key the authenticator keeps on the device, or one it may copy elsewhere. */
const hardware = "hwk";
const software = "swk";

/**
 * What a factor keeps in its secret: the subject's user handle, and the challenge its binding answers
 * with its end (kept after binding, read by nothing then).
 */
const secretShape = z.strictObject({
	handle: z.string().min(1),
	challenge: z.string().min(1),
	until: z.number(),
});
/** What a challenge keeps for its answer: the challenge, and its end on the kernel's clock. */
const keptShape = z.strictObject({ challenge: z.string().min(1), until: z.number() });

const read = <T>(shape: z.ZodType<T>, value: unknown): T | undefined => {
	const parsed = shape.safeParse(value);
	return parsed.success ? parsed.data : undefined;
};
/** The JSON text's value, or undefined if it is not JSON. */
const json = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};
const secretOf = (secret: string) => read(secretShape, json(secret));
/**
 * What mfa hands back: the factor's credential, its pending secret, or what its challenge kept. mfa
 * gives back only what it sealed, so one that does not read is a store fault, never a refusal.
 */
const stored = <T>(value: T | undefined): T => {
	if (value === undefined) throw new Unavailable("mfa-webauthn");
	return value;
};
const credentialIn = (state: unknown) => stored(credentialOf(state));
const amrOf = (credential: Credential) => [credential.backupEligible ? software : hardware];

export interface KindParts {
	readonly ceremonies: Ceremonies;
	readonly verification: Verification;
	readonly attributes: () => Pick<SubjectAttributes, "of">;
	/** The name shown when the subject has none to show. */
	readonly displayName: string;
	readonly random: (n: number) => Uint8Array;
}

export function webauthnKind(p: KindParts): FactorKind {
	/**
	 * The subject's name, never its email: an authenticator and a device's passkey list keep what it
	 * shows. Else the operator's name, which names no one.
	 */
	const nameOf = async (subject: string) => {
		const answer = await p.attributes().of(subject);
		const known = answer.kind === "known" ? answer.attributes : {};
		return showable(known[userAttribute.name]) ?? p.displayName;
	};
	/** A binding's first proof answers the creation its secret kept. */
	const attestation = async (secret: string, response: unknown): Promise<Verified> => {
		const { challenge, handle, until } = stored(secretOf(secret));
		const attested = await p.ceremonies.attest(response, challenge, handle, p.verification, until);
		if (attested.kind !== "attested") return { kind: "invalid" };
		return { kind: "valid", state: attested.credential, amr: amrOf(attested.credential) };
	};
	/** Any later proof answers the request the factor's last challenge kept. */
	const assertion = async (state: unknown, response: unknown, kept?: string): Promise<Verified> => {
		const credential = credentialIn(state);
		// No challenge kept: the proof answers nothing this factor asked, or one already used.
		if (kept === undefined) return { kind: "invalid" };
		const { challenge, until } = stored(read(keptShape, json(kept)));
		const asserted = await p.ceremonies.assert(
			response,
			challenge,
			credential,
			p.verification,
			until,
		);
		if (asserted.kind === "asserted") {
			return { kind: "valid", state: asserted.credential, amr: amrOf(asserted.credential) };
		}
		// A count that did not go up is an assertion older than one already used.
		return { kind: asserted.reason === "sign-count" ? "replayed" : "invalid" };
	};
	return {
		kind: "webauthn",
		amr: [hardware, software],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		// The handle is the subject's, so this tells apart only a credential bound twice to one subject.
		uniqueSecret: ({ secret, state }) => {
			const handle = secretOf(secret)?.handle;
			const credential = credentialOf(state);
			return handle && credential ? `${handle}\n${credential.id}` : undefined;
		},
		enroll: async (subject, held: readonly Opened[]) => {
			const handle =
				held.map((factor) => secretOf(factor.secret)?.handle).find((h) => h !== undefined) ??
				freshHandle(p.random);
			const exclude = held.flatMap((factor) => credentialOf(factor.state)?.id ?? []);
			const { options, challenge, until } = p.ceremonies.creation(
				{ handle, name: await nameOf(subject) },
				exclude,
				p.verification,
				{ discoverable: false },
			);
			return { secret: JSON.stringify({ handle, challenge, until }), show: options as object };
		},
		// Good until webauthn's end (`challenge-lifetime`) or the caller's, whichever comes first.
		challenge: async (_subject, factor, latest) => {
			const credential = credentialIn(factor.state);
			const { options, challenge, until } = p.ceremonies.request([credential], p.verification);
			const kept = JSON.stringify({ challenge, until: Math.min(until, latest) });
			return { kind: "sent", show: options as object, kept };
		},
		verify: async (secret, state, proof, kept) =>
			state === null ? attestation(secret, json(proof)) : assertion(state, json(proof), kept),
	};
}
