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
 * A session's renewal nonce: what binds a `UserSession` record to the one
 * express session a renewal moved it to. `LoginCompletion.renewSession`
 * mints one into the new cookie session, `recordSecondFactor` records it on
 * the record in the same write as the escalation, and admission refuses a
 * cookie session whose nonce is not the record's — so an old express id a
 * concurrent request saved back after the renewal names the record and is
 * still refused.
 *
 * Server-side state: it lives in the cookie session's store and the
 * session record, never on the wire. 128 bits from the CSPRNG, so no two
 * renewals share one; base64url, 22 characters.
 */
import { randomBytes } from "node:crypto";
/** The bytes a renewal nonce is minted from: 128 bits. */
export const RENEWAL_NONCE_BYTES = 16;
const RENEWAL_NONCE = /^[A-Za-z0-9_-]{22}$/;
/** A fresh renewal nonce: {@link RENEWAL_NONCE_BYTES} from the CSPRNG, base64url. */
export const newRenewalNonce = () => randomBytes(RENEWAL_NONCE_BYTES).toString("base64url");
/** Whether `value` is a renewal nonce as {@link newRenewalNonce} spells one. */
export const isRenewalNonce = (value) => typeof value === "string" && RENEWAL_NONCE.test(value);
