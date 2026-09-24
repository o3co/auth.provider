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
 * What the session router answers with internally.
 *
 * The adapter port — `FederationProvider`, `FederationProfile`, the
 * capability interfaces and their guards — moved to
 * `@o3co/auth-provider-core` with #626 P1, so that the type a federation is
 * registered with is the type `oauth` and `federation-grants` read. This
 * result type did not: nothing outside this package returns one.
 */

export type FederationResult<T> =
	| { readonly ok: true; readonly value: T }
	| {
			readonly ok: false;
			readonly status: number;
			/**
			 * The OAuth `error`. One outside RFC 6749's `1*NQSCHAR` is sent as
			 * `invalid_request` under a 4xx `status`, `server_error` otherwise.
			 */
			readonly error: string;
			/** The `error_description`; a character outside RFC 6749's set is sent as `?`. */
			readonly errorDescription: string;
	  };
