import { generateKeyPairSync } from "node:crypto";
import type { z } from "zod";
import type { section } from "./signing/section.ts";

export type KeysSettings = z.input<typeof section>;

/** The keys part of a test's configuration: a fresh Ed25519 signing key, unless the test sets one. */
export function keysConfig(settings: Partial<KeysSettings> = {}) {
	const signing = settings.signing ?? {
		kid: "test",
		alg: "EdDSA",
		"private-key": generateKeyPairSync("ed25519")
			.privateKey.export({ format: "pem", type: "pkcs8" })
			.toString(),
	};
	return { keys: { ...settings, signing } };
}
