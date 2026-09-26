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
 * The production guard on storing upstream refresh tokens unencrypted
 * (OR-12 / #473), shared by the two stores that hold them: the session-bound
 * federation tokens (#293) and the federation grants of #593.
 *
 * One escape hatch, not two: `FEDERATION_TOKENS_ALLOW_INSECURE=1` is about
 * "IdP refresh tokens at rest without encryption", which is what both stores
 * would be doing. A second variable would let a deployment permit it for one
 * and be surprised by the other. The `label` is what the messages name, so
 * an operator is told which store refused.
 */
const PRODUCTION_ENVS = new Set(["production", "staging"]);
/**
 * OR-12 / #473 — refuse to construct a federation-token store with
 * `mode = "allow-plaintext"` where plaintext is not acceptable, unless the
 * operator explicitly sets `FEDERATION_TOKENS_ALLOW_INSECURE=1`. Logs a
 * CRITICAL line when the escape hatch is active. Everywhere else it emits a
 * soft `console.warn` but does not throw.
 *
 * Plaintext is refused when any of these holds:
 *   - the explicit `environment` is `production` or `staging`;
 *   - `NODE_ENV` is `production` or `staging` (always consulted; the sole
 *     signal when no environment is passed);
 *   - `deploymentMode` is `"multi"`.
 *
 * Runs at factory time before the DI container is fully wired, so direct
 * `console.*` is the appropriate emission channel (no Logger available yet).
 */
export function validateEncryptionMode(label, mode, { environment, deploymentMode }) {
    if (mode === "required")
        return;
    const allowInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE === "1";
    // Both names are checked, and the one that matched is the one reported:
    // an operator whose CONFIG_ENV says production should not be told about
    // NODE_ENV, and vice versa.
    const productionEnvironment = [environment, process.env.NODE_ENV].find((name) => name !== undefined && PRODUCTION_ENVS.has(name));
    const reasons = [];
    if (productionEnvironment !== undefined) {
        reasons.push(`the environment is "${productionEnvironment}"`);
    }
    if (deploymentMode === "multi") {
        reasons.push('deployment.mode is "multi" (a multi-replica deployment is never a development box)');
    }
    if (reasons.length > 0) {
        const because = reasons.join(" and ");
        if (allowInsecure) {
            // Factory-time emission, no Logger available yet.
            console.error(`[${label}] CRITICAL: running with mode="${mode}" although ${because}, ` +
                "because FEDERATION_TOKENS_ALLOW_INSECURE=1. Federation tokens (IdP refresh tokens) " +
                "are stored UNENCRYPTED. This is a security risk. Do NOT use in normal production.");
            return;
        }
        throw new Error(`[${label}] mode "${mode}" is refused because ${because}. ` +
            'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
            "FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).");
    }
    // Dev/test: warn but do not throw. Factory-time emission, no Logger available yet.
    console.warn(`[${label}] WARNING: mode="${mode}" stores federation tokens (IdP refresh tokens) ` +
        "unencrypted. Use only in development/test environments.");
}
