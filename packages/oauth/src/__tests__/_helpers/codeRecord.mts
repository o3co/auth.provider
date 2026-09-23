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
import type { Code } from "@o3co/auth-provider-core";

/**
 * A `Code` for a stub repository: the fields a test names, every other one
 * `undefined` (#626). `Code` names each field as a required key so that a
 * repository's copy cannot forget one; a stub that returns a fixed record has
 * nothing to forget, and spelling eight `undefined`s into each would hide
 * the fields the test is about.
 */
export const codeRecord = (
	fields: Pick<Code, "code" | "client_id" | "redirect_uri"> & Partial<Code>,
): Code => ({
	code_challenge: undefined,
	code_challenge_method: undefined,
	nonce: undefined,
	sid: undefined,
	acr: undefined,
	expiresIn: undefined,
	grantedScope: undefined,
	grantedAudience: undefined,
	...fields,
});
