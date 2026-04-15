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

export { extractEd25519PublicKeyBytes } from "./ed25519Utils.mjs";
export { type Algorithm, createVerifier } from "./factory.mjs";
// Ed25519RawVerifier and Ed25519PrehashVerifier intentionally NOT re-exported — they
// dynamically import @noble/ed25519 at runtime, which is an optional peer dep.
// Use createVerifier("ed25519_raw") / createVerifier("ed25519_prehash") or import directly.
export { JwsVerifier } from "./jws.mjs";
export type {
	ParsedMessage,
	SignatureVerifier,
	VerificationContext,
	VerificationResult,
} from "./types.mjs";
