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
export { createDidGrant, type DidGrantOptions } from "./did.mjs";
export { didConfigSchema, oauthDidModule, type DidModuleOptions } from "./module.mjs";
export { extractVerificationKey, type ExtractedKey } from "./resolver/extractKey.mjs";
export type { DidDocument, DidDocumentResolver, VerificationMethod } from "./resolver/types.mjs";
export { detectAlgorithm } from "./verifiers/detect.mjs";
export { createDefaultVerifierRegistry, createVerifier, type Algorithm, type VerifierFactory } from "./verifiers/factory.mjs";
export { VerifierRegistry } from "./verifiers/registry.mjs";
export type { ParsedMessage, SignatureVerifier, VerificationContext, VerificationResult } from "./verifiers/types.mjs";
