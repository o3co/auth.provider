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
import { createPrivateKey } from "node:crypto";
import { resolveClientSecret } from "@o3co/auth-provider-session";
import { importPKCS8 } from "jose";
import * as oidc from "openid-client";
/** `application/x-www-form-urlencoded`, as RFC 6749 §2.3.1 requires before base64. */
const formUrlEncode = (value) => new URLSearchParams([["v", value]]).toString().slice(2);
const message = (err) => (err instanceof Error ? err.message : String(err));
/** `client_secret_basic` with a secret that may be resolved per request. */
export function clientSecretBasic(clientSecret) {
    // oauth4webapi awaits the callback, so the resolver can be asynchronous;
    // openid-client's declared type is the synchronous narrowing, hence the cast.
    const auth = async (_as, client, _body, headers) => {
        const secret = await resolveClientSecret(clientSecret);
        const credentials = Buffer.from(`${formUrlEncode(client.client_id)}:${formUrlEncode(secret)}`).toString("base64");
        headers.set("authorization", `Basic ${credentials}`);
    };
    return auth;
}
function inferAlg(label, key) {
    switch (key.asymmetricKeyType) {
        case "rsa":
            return "RS256";
        case "rsa-pss":
            return "PS256";
        case "ec": {
            const curve = key.asymmetricKeyDetails?.namedCurve;
            if (curve === "prime256v1")
                return "ES256";
            if (curve === "secp384r1")
                return "ES384";
            if (curve === "secp521r1")
                return "ES512";
            if (curve === "secp256k1")
                return "ES256K";
            throw new Error(`${label}: privateKey uses EC curve ${String(curve)}, which has no JWS algorithm; set privateKey.alg`);
        }
        case "ed25519":
            return "EdDSA";
        default:
            throw new Error(`${label}: privateKey of type ${String(key.asymmetricKeyType)} is not usable for private_key_jwt; set privateKey.alg`);
    }
}
/** `private_key_jwt` from a PEM key, importing it once at construction. */
export async function privateKeyJwt(label, privateKey) {
    const spec = typeof privateKey === "string" ? { pem: privateKey } : privateKey;
    if (typeof spec.pem !== "string" || !spec.pem.includes("-----BEGIN")) {
        throw new Error(`${label}: privateKey must be a PEM-encoded PKCS#8 private key`);
    }
    let keyObject;
    try {
        keyObject = createPrivateKey(spec.pem);
    }
    catch (err) {
        throw new Error(`${label}: privateKey could not be parsed: ${message(err)}`, { cause: err });
    }
    const alg = spec.alg ?? inferAlg(label, keyObject);
    let key;
    try {
        key = await importPKCS8(spec.pem, alg, { extractable: false });
    }
    catch (err) {
        throw new Error(`${label}: privateKey cannot sign ${alg}: ${message(err)}`, { cause: err });
    }
    return oidc.PrivateKeyJwt(spec.kid === undefined ? key : { key, kid: spec.kid });
}
/** The one client authentication method the credentials describe. */
export async function clientAuthFor(label, credentials) {
    // An empty static secret is a misconfiguration to refuse now, not at the
    // first token request; a resolver function is checked when it runs.
    if (credentials.clientSecret === "") {
        throw new Error(`${label}: clientSecret must not be empty`);
    }
    const hasSecret = credentials.clientSecret !== undefined;
    const hasKey = credentials.privateKey !== undefined;
    if (hasSecret === hasKey) {
        throw new Error(`${label}: set exactly one of clientSecret (client_secret_basic) or privateKey (private_key_jwt)`);
    }
    return hasSecret
        ? clientSecretBasic(credentials.clientSecret)
        : privateKeyJwt(label, credentials.privateKey);
}
