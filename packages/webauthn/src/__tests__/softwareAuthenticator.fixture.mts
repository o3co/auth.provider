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
 * A software authenticator, for tests that run `@simplewebauthn/server`'s
 * real verification: one P-256 credential (COSE ES256), registered by a
 * `none` attestation and asserted by an ECDSA signature over the
 * authenticator data and the client data's hash, counter 1. A `none`
 * attestation signs nothing, so a registration's client data is the test's
 * to write; an assertion's is signed as written. Not a test file.
 */

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

/** The authenticator data's flags (WebAuthn §6.1): user present, user verified, attested credential data. */
const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

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

/** What a ceremony's response carries beyond its challenge. */
export interface CeremonyOptions {
	/** Laid over the client data a same-origin browser sends: `type`, `challenge`, `origin` and `crossOrigin: false`. */
	readonly clientData?: Readonly<Record<string, unknown>>;
	/** How the client data's bytes are written into the response; canonical base64url unless given. */
	readonly encode?: (clientDataJSON: Buffer) => string;
}

export interface SoftwareAuthenticator {
	/** Its credential id, base64url. */
	readonly credentialId: string;
	/** Its COSE public key. */
	readonly publicKey: Uint8Array<ArrayBuffer>;
	/** A registration response of the credential, as a browser sends it after `navigator.credentials.create()`. */
	register(challenge: string, options?: CeremonyOptions): RegistrationResponseJSON;
	/** An assertion by the credential, as a browser sends it after `navigator.credentials.get()`. */
	assert(challenge: string, options?: CeremonyOptions): AuthenticationResponseJSON;
}

export function softwareAuthenticator(relyingParty: {
	readonly rpId: string;
	readonly origin: string;
	/**
	 * The user handle a discoverable credential returns with each assertion, base64url. Absent,
	 * the credential returns none, as a non-discoverable one does.
	 */
	readonly userHandle?: string;
}): SoftwareAuthenticator {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = publicKey.export({ format: "jwk" });
	// COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
	const cose = Buffer.concat([
		Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
		Buffer.from(jwk.x as string, "base64url"),
		Buffer.from([0x22, 0x58, 0x20]),
		Buffer.from(jwk.y as string, "base64url"),
	]);
	const credentialIdBytes = randomBytes(16);
	const credentialId = credentialIdBytes.toString("base64url");
	const rpIdHash = createHash("sha256").update(relyingParty.rpId).digest();

	const clientDataOf = (type: string, challenge: string, options: CeremonyOptions): Buffer =>
		Buffer.from(
			JSON.stringify({
				type,
				challenge,
				origin: relyingParty.origin,
				crossOrigin: false,
				...options.clientData,
			}),
		);
	const encoded = (clientData: Buffer, options: CeremonyOptions): string =>
		options.encode?.(clientData) ?? clientData.toString("base64url");

	return {
		credentialId,
		publicKey: new Uint8Array(cose),
		register(challenge, options = {}) {
			const idLength = Buffer.alloc(2);
			idLength.writeUInt16BE(credentialIdBytes.length);
			const authData = Buffer.concat([
				rpIdHash,
				Buffer.from([UP | UV | AT]),
				Buffer.alloc(4),
				Buffer.alloc(16),
				idLength,
				credentialIdBytes,
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
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				response: {
					clientDataJSON: encoded(clientDataOf("webauthn.create", challenge, options), options),
					attestationObject: attestationObject.toString("base64url"),
					transports: ["internal"],
				},
				clientExtensionResults: {},
			};
		},
		assert(challenge, options = {}) {
			const clientData = clientDataOf("webauthn.get", challenge, options);
			const counter = Buffer.alloc(4);
			counter.writeUInt32BE(1);
			const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([UP | UV]), counter]);
			const signature = sign(
				"sha256",
				Buffer.concat([authenticatorData, createHash("sha256").update(clientData).digest()]),
				privateKey,
			);
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				response: {
					clientDataJSON: encoded(clientData, options),
					authenticatorData: authenticatorData.toString("base64url"),
					signature: signature.toString("base64url"),
					...(relyingParty.userHandle === undefined ? {} : { userHandle: relyingParty.userHandle }),
				},
				clientExtensionResults: {},
			};
		},
	};
}

/**
 * Base64url that is not canonical but decodes, as `@simplewebauthn/server` decodes it, to the
 * same bytes: the first `A` (a sextet of 0) of the canonical encoding written as `replacement`,
 * a character outside the alphabet, which the library's decoder also reads as 0. The bytes must
 * encode to at least one `A` before the last character: `"@@@"` in them guarantees one.
 */
export const nonCanonicalBase64url =
	(replacement: string) =>
	(bytes: Buffer): string => {
		const canonical = bytes.toString("base64url");
		const at = canonical.indexOf("A");
		if (at < 0 || at === canonical.length - 1) {
			throw new Error("the bytes encode to no A before the last character");
		}
		return `${canonical.slice(0, at)}${replacement}${canonical.slice(at + 1)}`;
	};
