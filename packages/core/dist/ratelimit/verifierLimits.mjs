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
/** The declarations boot holds while it parses the module sections. */
let declaredWhileParsing;
/**
 * Runs `parse` with `declared` (prefix to setting) as the verifier limits a
 * limiter section refuses, and restores what was held before. `parse` is
 * synchronous, so no other parse sees them.
 * @internal
 */
export function withVerifierLimitDeclarations(declared, parse) {
    const outer = declaredWhileParsing;
    declaredWhileParsing = declared;
    try {
        return parse();
    }
    finally {
        declaredWhileParsing = outer;
    }
}
/**
 * Where the limit under `prefix` is set when a verifier owns it — the
 * setting a refusal names: the one `declared` holds (by default, what boot
 * holds while parsing), else `undefined`. Core names no prefix itself: only
 * a declaration makes one a verifier's.
 */
export const verifierLimitSetting = (prefix, declared = declaredWhileParsing) => declared?.get(prefix);
/** Why a limiter's `limits` may not name `prefix`, or `undefined` when it may. */
const verifierLimitProblem = (prefix) => {
    const setting = verifierLimitSetting(prefix);
    return setting === undefined
        ? undefined
        : `"${prefix}" is a verifier's own attempt limit, which no limiter's limits may set: set ${setting} instead`;
};
/**
 * A limiter section's `limits` check (`superRefine`): an issue at each entry
 * naming a verifier's prefix.
 */
export function refuseVerifierLimitEntries(limits, ctx) {
    for (const prefix of Object.keys(limits)) {
        const problem = verifierLimitProblem(prefix);
        if (problem !== undefined)
            ctx.addIssue({ code: "custom", path: [prefix], message: problem });
    }
}
/**
 * A `rateLimitBudgets` claim of a prefix a verifier limits itself: it
 * answers `null`, as every claim does, and declares the setting the limit is
 * made at. Frozen.
 */
export function verifierLimitClaim(declaration) {
    const verifier = Object.freeze({ setting: declaration.setting });
    return Object.freeze(Object.assign(() => null, { verifier }));
}
