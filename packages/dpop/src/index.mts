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

export { athMatches, computeAth } from "./ath.mjs";
export { DPoPError, type DPoPErrorCode, type DPoPReasonCode } from "./errors.mjs";
// `normalizeHtu` intentionally NOT exported per spec §7 — internal utility
// only. The verifier consumes it via relative import. Promoting it to the
// public surface would commit the package to maintaining its exact shape
// (semver lock); the spec keeps it deliberately tight.
export { createMemoryDPoPReplayStore } from "./memory/replay-store.mjs";
export { dpopConfigSchema, dpopModule } from "./module.mjs";
export type { DPoPProof, DPoPProofClaims } from "./proof.mjs";
export { parseProof } from "./proof.mjs";
export type { DPoPReplayStore } from "./replay-store.mjs";
export { computeJkt } from "./thumbprint.mjs";
export { createDPoPMechanism, type DPoPMechanismOptions } from "./verifier.mjs";
