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
import { calculateJwkThumbprint, type JWK } from "jose";

/**
 * Compute the JWK Thumbprint (JKT) for a public JWK using SHA-256.
 *
 * RFC 7638 §3 canonical JWK member selection + SHA-256 hash → base64url.
 * Used to bind a DPoP access token to the client's public key per
 * RFC 9449 §6.1 and to derive the `cnf.jkt` claim.
 *
 * Per Wave 2 Phase 2 spec §5.4 + RFC 7638.
 */
export const computeJkt = async (jwk: JWK): Promise<string> => {
	return calculateJwkThumbprint(jwk, "sha256");
};
