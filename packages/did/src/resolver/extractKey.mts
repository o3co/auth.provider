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
import type { DidDocument, JsonWebKey } from "./types.mjs";

export type ExtractedKey =
	| { format: "jwk"; key: JsonWebKey }
	| { format: "multibase"; key: string };

/**
 * Extract a verification key from a DID Document for the given DID.
 *
 * Matching logic: find a verificationMethod whose `controller` equals the DID,
 * or whose `id` starts with `${did}#`.
 *
 * @throws if no verificationMethod array is present, no matching method is found,
 *         or the matching method has no key material.
 */
export async function extractVerificationKey(doc: DidDocument, did: string): Promise<ExtractedKey> {
	if (!doc.verificationMethod || doc.verificationMethod.length === 0) {
		throw new Error(`DID Document for ${did} has no verificationMethod`);
	}

	const method = doc.verificationMethod.find(
		(vm) => vm.controller === did || vm.id.startsWith(`${did}#`),
	);

	if (!method) {
		throw new Error(`No verificationMethod found for DID ${did}`);
	}

	if (method.publicKeyJwk !== undefined) {
		return { format: "jwk", key: method.publicKeyJwk };
	}

	if (method.publicKeyMultibase !== undefined) {
		return { format: "multibase", key: method.publicKeyMultibase };
	}

	throw new Error(
		`verificationMethod ${method.id} has no key material (publicKeyJwk or publicKeyMultibase)`,
	);
}
