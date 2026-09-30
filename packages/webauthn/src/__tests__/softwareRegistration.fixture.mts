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
 * A software authenticator's registration response, for tests that run
 * `@simplewebauthn/server`'s real verification: a `none` attestation of a
 * fresh P-256 credential (COSE ES256) over a challenge. A `none` attestation
 * signs nothing, so the client data is the test's to write. Not a test file.
 */

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";

/** The authenticator data's flags (WebAuthn §6.1): user present, user verified, attested credential data. */
const FLAGS = 0x01 | 0x04 | 0x40;

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

export interface SoftwareRegistrationOptions {
	readonly rpId: string;
	readonly origin: string;
	readonly challenge: string;
	/** Laid over the client data a same-origin browser sends: `type`, `challenge`, `origin` and `crossOrigin: false`. */
	readonly clientData?: Readonly<Record<string, unknown>>;
}

/** A registration response of a new credential, as a browser sends it after `navigator.credentials.create()`. */
export function softwareRegistration(
	options: SoftwareRegistrationOptions,
): RegistrationResponseJSON {
	const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = publicKey.export({ format: "jwk" });
	// COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
	const cose = Buffer.concat([
		Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
		Buffer.from(jwk.x as string, "base64url"),
		Buffer.from([0x22, 0x58, 0x20]),
		Buffer.from(jwk.y as string, "base64url"),
	]);
	const credentialId = randomBytes(16);
	const idLength = Buffer.alloc(2);
	idLength.writeUInt16BE(credentialId.length);
	const authData = Buffer.concat([
		createHash("sha256").update(options.rpId).digest(),
		Buffer.from([FLAGS]),
		Buffer.alloc(4),
		Buffer.alloc(16),
		idLength,
		credentialId,
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
			challenge: options.challenge,
			origin: options.origin,
			crossOrigin: false,
			...options.clientData,
		}),
	);
	const id = credentialId.toString("base64url");
	return {
		id,
		rawId: id,
		type: "public-key",
		response: {
			clientDataJSON: clientDataJSON.toString("base64url"),
			attestationObject: attestationObject.toString("base64url"),
			transports: ["internal"],
		},
		clientExtensionResults: {},
	};
}
