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
// Minimal subset of the Web Crypto API JsonWebKey interface (public key fields only).
// Defined locally to avoid a DOM lib dependency in this Node.js package.
export interface JsonWebKey {
	kty?: string;
	crv?: string;
	x?: string;
	y?: string;
}

export interface VerificationMethod {
	id: string;
	type: string;
	controller: string;
	publicKeyJwk?: JsonWebKey;
	publicKeyMultibase?: string;
}

export interface DidDocument {
	id: string;
	verificationMethod?: VerificationMethod[];
}

export interface DidDocumentResolver {
	resolve(did: string): Promise<DidDocument>;
}
