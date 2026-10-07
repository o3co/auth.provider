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
export const noStoreNoReferrer = (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    // The challenge and the handle travel in URLs; neither may leave in a
    // Referer header to whatever the page links to.
    res.set("Referrer-Policy", "no-referrer");
    next();
};
/** A navigation's refusal: plain text, never a JSON body a user would see raw. */
export const plain = (res, status, message) => {
    res.status(status).type("text/plain").send(message);
};
/** The page's refusal, in `/oauth/consent`'s shape. */
export const jsonError = (res, status, error, description) => {
    res.status(status).json({ error, error_description: description });
};
/**
 * One answer for every challenge with nothing behind it — answered, expired,
 * never issued, issued to another browser — so the response does not say
 * which. The sibling's wording, for the page that already handles it.
 */
export const NO_PENDING = "no pending consent for this challenge: it was answered, has expired, or was not issued to this session; start again";
/** Where a declined flow ends: the client's own URI, with what it needs and nothing else. */
export function clientReturn(intent, error) {
    const url = new URL(intent.redirectUri);
    url.searchParams.set("grant_id", intent.grantId);
    url.searchParams.set("state", intent.clientState);
    if (error !== undefined)
        url.searchParams.set("error", error);
    return url.href;
}
