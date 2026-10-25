import { createHash } from "node:crypto";
import type { Client, Section } from "@mod/clients";
import type { GrantInput } from "@mod/grants";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { isWellFormedSubject } from "@mod/users";
import { decodeJwt } from "jose";
import { z } from "zod";
import type { DelegatedAssertions, DelegatedCheck } from "../contract.ts";

/** The client's section: whether, being public, it may present a delegated assertion without a key to prove. */
export interface DelegatedClient {
	readonly "accept-unbound": boolean;
}

export const delegatedClient: Section<DelegatedClient> = {
	name: "jwt-bearer",
	schema: z.strictObject({
		"accept-unbound": z
			.boolean()
			.prefault(false)
			.describe(
				"Lets this public client present a delegated issuer's assertion that names no key (no digest in its nonce) without proving one by DPoP: for apps already sent out that make no DPoP key. A leaked assertion can then be used once, before its owner, until it ages out, and the token is bound to no key. Each is logged; one naming a key is proved still. Read for registered clients only.",
			),
	}),
};

/** Whether the client may present an assertion that names no key: registered, so the operator said so. */
export const acceptsUnbound = (client: Client) =>
	client.registered && client.section(delegatedClient)["accept-unbound"];

/** The `iss` an assertion names, unverified, where it is read as a JWT and names one as a string. */
export function sentIssuerOf(assertion: string): string | undefined {
	try {
		const { iss } = decodeJwt(assertion);
		return typeof iss === "string" ? iss : undefined;
	} catch {
		return undefined;
	}
}

/** A digest of a key: SHA-256 in base64url, 43 characters. */
const digestShape = /^[A-Za-z0-9_-]{43}$/;
const checkShape = z.discriminatedUnion("kind", [
	z.object({
		kind: z.literal("valid"),
		subject: z.string().refine(isWellFormedSubject),
		issuedAt: z.number().finite(),
		expiresAt: z.number().finite(),
		clients: z.array(z.string().min(1)).min(1),
		holderDigest: z.string().regex(digestShape).optional(),
	}),
	z.object({ kind: z.literal("invalid") }),
]);

/** The delegate's answer, read at this boundary: any throw is Unavailable, and so is any answer of no shape the contract gives. */
export async function checkedBy(
	delegate: DelegatedAssertions,
	assertion: string,
): Promise<DelegatedCheck> {
	let told: unknown;
	try {
		told = await delegate.check(assertion);
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("jwt-bearer");
	}
	const read = checkShape.safeParse(told);
	if (!read.success) throw new Unavailable("jwt-bearer");
	return read.data as DelegatedCheck;
}

/** Uses the assertion up with its delegate, read at this boundary: only `spent` lets a token be issued. */
export async function spentBy(
	delegate: DelegatedAssertions,
	assertion: string,
): Promise<"spent" | "replayed"> {
	let told: unknown;
	try {
		told = await delegate.spend(assertion);
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("jwt-bearer");
	}
	if (told !== "spent" && told !== "replayed") throw new Unavailable("jwt-bearer");
	return told;
}

/** Whether the request proves, by DPoP, the key whose digest the assertion names. */
export const holds = (binding: GrantInput["binding"], digest: string | undefined) =>
	digest !== undefined &&
	binding?.tokenType === "DPoP" &&
	createHash("sha256").update(binding.confirmation, "ascii").digest("base64url") === digest;
