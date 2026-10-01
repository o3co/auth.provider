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
 * A software passkey: a P-256 key whose public half is kept as a WebAuthn
 * store keeps one (COSE), and assertions over a challenge the provider
 * issued, signed as an authenticator signs them — authenticator data (the RP
 * id's hash, the flags, the counter) and the client data's hash, ECDSA over
 * SHA-256, DER. Its registration is a `none` attestation, which signs
 * nothing: anyone holding the credential id and the public key can make it.
 * Not a test file.
 */

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

/**
 * The authenticator data's flags (WebAuthn §6.1): user present, user verified, backup eligible
 * (BE), backed up (BS), attested credential data (AT).
 */
const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 } as const;

/** A CBOR head of major type `major` and a length below 65536. */
function cborHead(major: number, length: number): Buffer {
	if (length < 24) return Buffer.from([(major << 5) | length]);
	if (length < 256) return Buffer.from([(major << 5) | 24, length]);
	const head = Buffer.alloc(3);
	head[0] = (major << 5) | 25;
	head.writeUInt16BE(length, 1);
	return head;
}

const cborText = (text: string): Buffer =>
	Buffer.concat([cborHead(3, Buffer.byteLength(text)), Buffer.from(text)]);
const cborBytes = (bytes: Buffer): Buffer => Buffer.concat([cborHead(2, bytes.length), bytes]);

export interface SoftwarePasskey {
	/** Its credential id, base64url. */
	readonly credentialId: string;
	/** The COSE public key. */
	readonly publicKey: Uint8Array;
	/** Whether it may be backed up (BE): a multi-device credential. */
	readonly backupEligible: boolean;
	/** Whether it is backed up (BS). */
	readonly backedUp: boolean;
	/** The counter the last assertion carried; each assertion increments it first, unless the passkey keeps none. */
	counter: number;
	/**
	 * An assertion over `challenge`. `tampered` signs other client data than
	 * it sends; `userHandle` is carried when given; `type` replaces the client
	 * data's `webauthn.get`.
	 */
	assert(
		challenge: string,
		options?: {
			readonly tampered?: boolean;
			readonly userHandle?: string;
			readonly type?: string;
		},
	): Record<string, unknown>;
	/** A registration of the credential over `challenge`, as a same-origin browser sends it: a `none` attestation, counter as it is. */
	register(challenge: string): Record<string, unknown>;
}

export function softwarePasskey(options: {
	readonly rpId: string;
	readonly origin: string;
	/** Backup-eligible (BE): a multi-device credential. Defaults to `backedUp`. */
	readonly backupEligible?: boolean;
	/** Backed up (BS): a synced passkey. A backed-up credential is backup-eligible. */
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
	const backupEligible = options.backupEligible ?? backedUp;
	const flags = FLAG.UP | FLAG.UV | (backupEligible ? FLAG.BE : 0) | (backedUp ? FLAG.BS : 0);
	const rpIdHash = createHash("sha256").update(options.rpId).digest();
	const count = (): Buffer => {
		const bytes = Buffer.alloc(4);
		bytes.writeUInt32BE(passkey.counter);
		return bytes;
	};
	const passkey: SoftwarePasskey = {
		credentialId: b64url(randomBytes(16)),
		publicKey: new Uint8Array(cose),
		backupEligible,
		backedUp,
		counter: options.counter === "none" ? 0 : (options.counter ?? 0),
		assert(challenge, assertOptions = {}) {
			if (keepsCounter) passkey.counter += 1;
			const clientData = (value: string) =>
				Buffer.from(
					JSON.stringify({
						type: assertOptions.type ?? "webauthn.get",
						challenge: value,
						origin: options.origin,
						crossOrigin: false,
					}),
				);
			const clientDataJSON = clientData(challenge);
			const signed = assertOptions.tampered === true ? clientData(`${challenge}x`) : clientDataJSON;
			const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([flags]), count()]);
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
					...(assertOptions.userHandle === undefined
						? {}
						: { userHandle: assertOptions.userHandle }),
				},
				clientExtensionResults: {},
			};
		},
		register(challenge) {
			const id = Buffer.from(passkey.credentialId, "base64url");
			const idLength = Buffer.alloc(2);
			idLength.writeUInt16BE(id.length);
			// The attested credential data: no AAGUID, the id, the COSE key.
			const authData = Buffer.concat([
				rpIdHash,
				Buffer.from([flags | FLAG.AT]),
				count(),
				Buffer.alloc(16),
				idLength,
				id,
				cose,
			]);
			// {"fmt": "none", "attStmt": {}, "authData": <bytes>}
			const attestationObject = Buffer.concat([
				Buffer.from([0xa3]),
				cborText("fmt"),
				cborText("none"),
				cborText("attStmt"),
				Buffer.from([0xa0]),
				cborText("authData"),
				cborBytes(authData),
			]);
			const clientDataJSON = Buffer.from(
				JSON.stringify({
					type: "webauthn.create",
					challenge,
					origin: options.origin,
					crossOrigin: false,
				}),
			);
			return {
				id: passkey.credentialId,
				rawId: passkey.credentialId,
				type: "public-key",
				response: {
					clientDataJSON: b64url(clientDataJSON),
					attestationObject: b64url(attestationObject),
					transports: ["internal"],
				},
				clientExtensionResults: {},
			};
		},
	};
	return passkey;
}
