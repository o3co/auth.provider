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
 * Asking a responder: the DER request POSTed through the guarded fetch, which holds the deadline,
 * the size cap and the no-redirect rule. A fetch that fails is `fetch_failed`, and an outage when
 * the source failed (`isSourceFailure`).
 */
import { isSourceFailure } from "./fetchGuard.mjs";
const OCSP_REQUEST_MEDIA_TYPE = "application/ocsp-request";
const OCSP_RESPONSE_MEDIA_TYPE = "application/ocsp-response";
/** POST `der` to `url` through `options.fetch`, expecting an OCSP response back. */
export const fetchResponse = async (options, url, der) => {
    const fetched = await options.fetch(url, {
        method: "POST",
        body: der,
        contentType: OCSP_REQUEST_MEDIA_TYPE,
        accept: OCSP_RESPONSE_MEDIA_TYPE,
        expectContentType: OCSP_RESPONSE_MEDIA_TYPE,
    });
    if (!fetched.ok) {
        return {
            ok: false,
            reason: "fetch_failed",
            detail: `${fetched.reason} (${fetched.detail})`,
            ...(fetched.cause !== undefined ? { cause: fetched.cause } : {}),
            ...(isSourceFailure(fetched.reason) ? { outage: true } : {}),
        };
    }
    return fetched;
};
