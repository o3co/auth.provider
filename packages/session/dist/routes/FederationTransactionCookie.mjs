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
import { createFederationTransactionStore, deriveFederationTransactionCookieName, } from "../federations/transaction.mjs";
/**
 * Attributes shared by the `Set-Cookie` that issues the cookie and the one
 * that clears it. `Path=/` and no `Domain`, as the `__Host-` name requires.
 */
const transactionCookieAttributes = {
    httpOnly: true,
    // `SameSite=None` is what makes the cookie reach a cross-site POST,
    // and every current browser drops such a cookie unless it is also
    // `Secure`. Apple refuses a non-`https` redirect URI anyway, so a
    // form_post federation is HTTPS-only regardless.
    secure: true,
    sameSite: "none",
    path: "/",
};
/** The transaction cookies, each federation's named from `sessionCookieName`. */
export const createTransactionCookie = (sessionCookieName) => {
    /**
     * The federation transaction store, over the express-session store the
     * session middleware mounted (taken off the request, not injected, so it
     * cannot point elsewhere). Absent means no session middleware — a
     * composition error the `form_post` start refuses.
     */
    const transactionStore = (req) => {
        const store = req.sessionStore;
        if (store == null || typeof store !== "object")
            return undefined;
        const candidate = store;
        if (typeof candidate.get !== "function" ||
            typeof candidate.set !== "function" ||
            typeof candidate.destroy !== "function") {
            return undefined;
        }
        return createFederationTransactionStore(candidate);
    };
    const transactionCookieName = (provider) => deriveFederationTransactionCookieName(sessionCookieName, provider.name);
    /**
     * Drop the transaction cookie. Called on every callback exit — success,
     * refusal and error alike — so a consumed or unusable transaction never
     * leaves a cookie behind for the next attempt to trip over.
     */
    const clearTransactionCookie = (provider, res) => {
        res.clearCookie(transactionCookieName(provider), transactionCookieAttributes);
    };
    return {
        transactionCookieName,
        transactionStore,
        transactionCookieAttributes,
        clearTransactionCookie,
    };
};
