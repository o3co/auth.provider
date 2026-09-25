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

/*
 * The seen-set scopes a store treats apart from the others.
 *
 * DPoP records every proof it sees under `dpop-proof:<jkt>`, before the
 * token endpoint's rate limit and before a protected resource verifies the
 * access token, so anyone can make it write. The in-process seen-set lets
 * those records fill only {@link DPOP_PROOF_REPLAY_SHARE} of its cap, and
 * keeps the rest for the consumers whose writes follow an authentication or
 * a rate limit (`private_key_jwt`, ID-JAG, WebAuthn). The prefix lives here,
 * where the store reads it, and `@o3co/auth-provider-dpop` writes under it.
 * It is part of the stored key an operator sees in Redis.
 */

/** The scope prefix DPoP records its proofs under: `dpop-proof:<jkt>`. */
export const DPOP_PROOF_REPLAY_SCOPE_PREFIX = "dpop-proof:";

/**
 * The share of the in-process seen-set's cap DPoP proofs may fill: 90%,
 * rounded up to a whole record, so a set of any size takes a proof.
 */
export const DPOP_PROOF_REPLAY_SHARE = 0.9;
