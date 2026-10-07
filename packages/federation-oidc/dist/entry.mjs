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
 * The one reading of a `core.federations` entry of type `oidc`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key written `null` reads as
 * absent, and an absent key stays absent: what it means — the default scopes,
 * discovery on, UserInfo when the issuer publishes it — is the provider's
 * reading (`oidc.mts`), never a default filled in here.
 */
import { z } from "zod";
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** `value`, and every object in it, without the keys written `null`; lists are left as written. */
function withoutNulls(value) {
    if (!isRecord(value))
        return value;
    return Object.fromEntries(Object.entries(value)
        .filter(([, inner]) => inner !== null)
        .map(([key, inner]) => [key, withoutNulls(inner)]));
}
const REQUIRED = "is required (a non-empty string)";
const required = z.string({ error: REQUIRED }).min(1, { error: REQUIRED });
const text = z.string({ error: "must be a string" });
/** A boolean, or its spelling as the string `"true"` or `"false"` (an environment variable's). */
const flag = z.preprocess((value) => (value === "true" ? true : value === "false" ? false : value), z.boolean({ error: "must be true or false" }));
const strings = z.array(text, { error: "must be a list of strings" });
const PRIVATE_KEY = "must be a PEM string or { pem, kid?, alg? }";
const pemString = z.string().min(1, { error: PRIVATE_KEY });
const pemObject = z.strictObject({ pem: required, kid: text.optional(), alg: text.optional() }, { error: (issue) => (issue.code === "invalid_type" ? PRIVATE_KEY : undefined) });
/**
 * A PEM string, or `{ pem, kid?, alg? }`: a string is read as the one, and
 * anything else as the other, so a refusal inside the object names its key
 * (`privateKey.kid`) rather than the key as a whole.
 */
const privateKey = z.unknown().transform((value, ctx) => {
    const result = (typeof value === "string" ? pemString : pemObject).safeParse(value);
    if (result.success)
        return result.data;
    for (const issue of result.error.issues)
        ctx.addIssue({ ...issue });
    return z.NEVER;
});
const endpoints = z.strictObject({
    authorizationEndpoint: text.optional(),
    tokenEndpoint: text.optional(),
    jwksUri: text.optional(),
    userinfoEndpoint: text.optional(),
    endSessionEndpoint: text.optional(),
}, { error: "must be an object of endpoint URLs" });
const entryKeys = z.strictObject({
    issuer: required,
    clientId: required,
    clientSecret: text.optional(),
    privateKey: privateKey.optional(),
    scopes: strings.optional(),
    discovery: flag.optional(),
    endpoints: endpoints.optional(),
    idTokenSignedResponseAlg: text.optional(),
    userInfo: flag.optional(),
    clockToleranceSeconds: z.number({ error: "must be a number" }).optional(),
    redirectAllowlist: strings.optional(),
    sessionDomain: text.optional(),
    authCallbackUrl: text.optional(),
    clientUrl: text.optional(),
});
/**
 * The schema of an `oidc` entry's own keys: strict (a key it does not name
 * refuses the entry), flat, and with exactly one of `clientSecret`
 * (`client_secret_basic`) and `privateKey` (`private_key_jwt`).
 */
export const oidcEntrySchema = z.preprocess(withoutNulls, entryKeys.refine((entry) => (entry.clientSecret === undefined) !== (entry.privateKey === undefined), {
    error: "must set exactly one of clientSecret (client_secret_basic) or privateKey (private_key_jwt)",
}));
