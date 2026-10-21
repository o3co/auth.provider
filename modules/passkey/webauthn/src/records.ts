import { z } from "zod";
import type { Credential } from "./contract.ts";

/** Whether `text` is unpadded base64url of 1 to `max` bytes: the one spelling of those bytes. */
export function isCanonical(text: unknown, max: number): text is string {
	if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) return false;
	const bytes = Buffer.from(text, "base64url");
	return bytes.length >= 1 && bytes.length <= max && bytes.toString("base64url") === text;
}

export const handleBytes = 64;
export const idBytes = 1023;
/** The most bytes a credential's id and a user handle may hold, as `isCanonical` takes them. */
export const credentialLimits = { idBytes, handleBytes } as const;

const canonical = (max: number) => z.string().refine((text) => isCanonical(text, max));
const credentialShape = z.object({
	id: canonical(idBytes),
	publicKey: canonical(4096),
	signCount: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
	userHandle: canonical(handleBytes),
	backupEligible: z.boolean(),
	backedUp: z.boolean(),
	transports: z.array(z.string()).optional(),
});

/** A credential in the shape webauthn writes, with its fields alone; none for any other value. */
export function credentialOf(value: unknown): Credential | undefined {
	const parsed = credentialShape.safeParse(value);
	if (!parsed.success) return undefined;
	const { transports, ...rest } = parsed.data;
	return { ...rest, ...(transports ? { transports } : {}) };
}

/** A new subject's user handle: 32 random bytes, unpadded base64url. */
export const freshHandle = (random: (n: number) => Uint8Array): string =>
	Buffer.from(random(32)).toString("base64url");
