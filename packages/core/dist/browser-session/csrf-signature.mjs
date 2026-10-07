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
 * The bounds of a CSRF token's signature, part of the `csrfTokenSigner`
 * contract: `sign` answers base64url of this many characters, the contract
 * suite holds a signer to it, and a consumer that builds tokens over a signer
 * reads the same two numbers.
 */
/**
 * The fewest characters a signature carries: 22 base64url characters are 132
 * bits, the fewest that reach 128, so a guessed signature passes once in at
 * least 2^128 tries.
 */
export const CSRF_SIGNATURE_MIN_LENGTH = 22;
/**
 * The most characters a signature carries: a token (`<expiry>.<nonce>.<signature>`)
 * then stays far inside the 4096 bytes a browser keeps of a cookie.
 */
export const CSRF_SIGNATURE_MAX_LENGTH = 512;
