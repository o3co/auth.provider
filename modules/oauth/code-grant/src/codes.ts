import { createHash } from "node:crypto";
import { z } from "zod";
import type { StoredCode } from "./store.ts";

/** What a code keeps from its issuing to its end. */
export interface CodeRecord {
	/** The record's format: this writes 2 and reads 2 and 1 (1 has no `authenticatedAtUnknown`); no other. */
	readonly format: 1 | 2;
	readonly state: "issued" | "consumed";
	readonly clientId: string;
	readonly redirectUri: string;
	readonly challenge: string;
	readonly nonce?: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session: string;
	readonly subject: string;
	readonly acr?: string;
	readonly amr: readonly string[];
	readonly authenticatedAt: number;
	readonly authenticatedAtUnknown?: true;
	readonly token?: { readonly reference: string; readonly expiresAt: number };
	readonly void?: boolean;
}

const recordShape = z.strictObject({
	format: z.union([z.literal(1), z.literal(2)]),
	state: z.enum(["issued", "consumed"]),
	clientId: z.string(),
	redirectUri: z.string(),
	challenge: z.string(),
	nonce: z.string().optional(),
	scope: z.array(z.string()),
	audience: z.array(z.string()),
	session: z.string(),
	subject: z.string(),
	acr: z.string().optional(),
	amr: z.array(z.string()),
	authenticatedAt: z.number(),
	authenticatedAtUnknown: z.literal(true).optional(),
	token: z.strictObject({ reference: z.string(), expiresAt: z.number() }).optional(),
	void: z.boolean().optional(),
});

/** A record as the store keeps it; only code-grant reads what it holds. */
export const toStored = (record: CodeRecord) => record as unknown as StoredCode;
/** A kept value's record, checked on every read; nothing for an unknown format, state or shape. */
export const fromStored = (kept: StoredCode): CodeRecord | undefined => {
	const read = recordShape.safeParse(kept);
	return read.success ? (read.data as CodeRecord) : undefined;
};

export const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** RFC 7636: a verifier is 43 to 128 unreserved characters; an S256 challenge is 43 base64url. */
export const verifierShape = /^[A-Za-z0-9._~-]{43,128}$/;
export const challengeShape = /^[A-Za-z0-9_-]{43}$/;
