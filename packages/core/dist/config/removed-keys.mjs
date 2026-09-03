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
 * The one way a removed config key dies (#366).
 *
 * Zod's default object behavior strips unknown keys before `superRefine`
 * sees the data, so without a raw-input check an operator's stale config
 * line (`legacyTokenCompat = true`) is silently ignored on upgrade — the
 * config sits in the file looking load-bearing while doing nothing. Every
 * key removal therefore detects on the raw input, via `z.preprocess`, and
 * fails boot naming the key, the release that removed it, and what to do.
 *
 * Before #366 that detection existed as two copy-pasted table+wrapper
 * blocks (`oauth.refreshToken`, `oauth.authorize`), and the next removal
 * would have copied whichever the author saw last. This helper is the one
 * spelling; `docs/release-policy.md` §"Retiring a config key" carries the
 * fail-vs-warn decision rule for choosing between it and the warn-and-
 * ignore treatment (`INERT_PKCE_KEYS` in `@o3co/auth-provider-oauth`).
 *
 * ## The coercion-walk caveat
 *
 * `z.preprocess` compiles to a pipe the `@o3co/ts.hocon` zod bridge does
 * not descend into, so any leaf wrapped by this helper loses the bridge's
 * free string coercion (#288's root cause). That is survivable because the
 * repo no longer relies on the bridge for coercion: every env-overridable
 * boolean goes through `coerceBooleanFromEnv` and every number through
 * `z.coerce.number()` **on the field itself** — a property owned by the
 * field, not by what happens to be wrapped around it, and pinned by the
 * standalone template's documented-env-overrides suite. Keep it that way
 * when adding fields under a wrapped section.
 *
 * Related mechanisms, deliberately NOT this helper:
 *
 * - **Enum shrink** (`legacyRtPolicy: z.enum(["reject"])`): removing a
 *   VALUE from a still-live key. Zod's `invalid_enum_value` already names
 *   the accepted values; a tombstone table would only restate it.
 * - **Moved keys** (`LEGACY_JWT_FIELDS`): the key still exists under a new
 *   shape, so the message is a migration pointer ("migrate to
 *   `oauth.jwt.signingKey.local.<field>`"), not a removal notice. Folding
 *   it here would either water the removal message down or teach this
 *   helper a second dialect.
 * - **Warn-and-ignore** (`INERT_PKCE_KEYS`): for keys whose ignored value
 *   leaves behavior strictly stronger — see the release-policy rule.
 */
import { z } from "zod";
/**
 * Wraps `schema` so that any key in `removed` still present on the RAW
 * input fails parse with a targeted, operator-facing message — instead of
 * being stripped silently by Zod's unknown-key handling.
 *
 * `sectionPath` is the config path the operator writes (`oauth.refreshToken`);
 * it prefixes the key in the message so the boot error names the exact line
 * to delete. Every removed key present is reported, not just the first.
 */
export function withRemovedKeys(sectionPath, removed, schema) {
    return z.preprocess((raw, ctx) => {
        if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
            const rawObj = raw;
            for (const entry of removed) {
                if (entry.name in rawObj) {
                    ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        message: `${sectionPath}.${entry.name} was removed in ${entry.removedIn}; see CHANGELOG. ` +
                            `${entry.note} Remove this field from your config.`,
                        path: [entry.name],
                    });
                }
            }
        }
        return raw;
    }, schema);
}
