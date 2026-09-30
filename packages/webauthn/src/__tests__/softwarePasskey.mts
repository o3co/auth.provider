/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A software passkey for the composed tests: a P-256 key whose public half
 * is kept as the WebAuthn factor keeps one (COSE, base64url), and assertions
 * signed as an authenticator signs them — authenticator data (the RP id's
 * hash, the flags, the counter) and the client data's hash, ECDSA over
 * SHA-256, DER. Not a test file.
 */

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

/** User present and user verified; backup eligible and backed up for a synced passkey (WebAuthn §6.1). */
const FLAGS = { device: 0x05, synced: 0x1d } as const;

export interface SoftwarePasskey {
	readonly credentialId: string;
	/** The COSE public key, base64url. */
	readonly publicKey: string;
	readonly backedUp: boolean;
	/** The counter the next assertion carries, once incremented; one that keeps none stays at 0. */
	counter: number;
	/** An assertion over `challenge`; `tampered` signs other client data than it sends. */
	assert(
		challenge: string,
		options?: { readonly tampered?: boolean; readonly userHandle?: string },
	): Record<string, unknown>;
}

export function softwarePasskey(options: {
	readonly rpId: string;
	readonly origin: string;
	readonly backedUp?: boolean;
	/** The counter before the first assertion; `"none"` for an authenticator that keeps none. */
	readonly counter?: number | "none";
}): SoftwarePasskey {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = publicKey.export({ format: "jwk" });
	// COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}, CBOR.
	const cose = Buffer.concat([
		Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
		Buffer.from(jwk.x as string, "base64url"),
		Buffer.from([0x22, 0x58, 0x20]),
		Buffer.from(jwk.y as string, "base64url"),
	]);
	const keepsCounter = options.counter !== "none";
	const backedUp = options.backedUp === true;
	const passkey: SoftwarePasskey = {
		credentialId: b64url(randomBytes(16)),
		publicKey: b64url(cose),
		backedUp,
		counter: options.counter === "none" ? 0 : (options.counter ?? 0),
		assert(challenge, assertOptions = {}) {
			if (keepsCounter) passkey.counter += 1;
			const clientData = (value: string) =>
				Buffer.from(
					JSON.stringify({
						type: "webauthn.get",
						challenge: value,
						origin: options.origin,
						crossOrigin: false,
					}),
				);
			const clientDataJSON = clientData(challenge);
			const signed = assertOptions.tampered === true ? clientData(`${challenge}x`) : clientDataJSON;
			const count = Buffer.alloc(4);
			count.writeUInt32BE(passkey.counter);
			const authenticatorData = Buffer.concat([
				createHash("sha256").update(options.rpId).digest(),
				Buffer.from([backedUp ? FLAGS.synced : FLAGS.device]),
				count,
			]);
			const signature = sign(
				"sha256",
				Buffer.concat([authenticatorData, createHash("sha256").update(signed).digest()]),
				privateKey,
			);
			return {
				id: passkey.credentialId,
				rawId: passkey.credentialId,
				type: "public-key",
				response: {
					clientDataJSON: b64url(clientDataJSON),
					authenticatorData: b64url(authenticatorData),
					signature: b64url(signature),
					...(assertOptions.userHandle === undefined ? {} : { userHandle: assertOptions.userHandle }),
				},
				clientExtensionResults: {},
			};
		},
	};
	return passkey;
}
