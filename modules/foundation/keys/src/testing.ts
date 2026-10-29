import { generateKeyPairSync } from "node:crypto";
import type { z } from "zod";
import type { section } from "./signing/section.ts";

export type KeysSettings = z.input<typeof section>;

let rsaPem: string | undefined;
/** One RSA key for the process: making one costs far more than an Ed25519 key, and a test needs no fresh one. */
const sharedRsaPem = () => {
	rsaPem ??= generateKeyPairSync("rsa", { modulusLength: 2048 })
		.privateKey.export({ format: "pem", type: "pkcs8" })
		.toString();
	return rsaPem;
};

/**
 * The keys part of a test's configuration: an RS256 signing key, the one ID tokens are signed with
 * unless the operator writes another, unless the test sets one.
 */
export function keysConfig(settings: Partial<KeysSettings> = {}) {
	const signing = settings.signing ?? { kid: "test", alg: "RS256", "private-key": sharedRsaPem() };
	return { keys: { ...settings, signing } };
}
