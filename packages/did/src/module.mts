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
import { z } from "zod";
import type { GrantModule } from "@o3co/auth-provider-core";
import { createDidGrant } from "./did.mjs";

export const didConfigSchema = z.object({
	did: z.object({
		enabled: z.boolean().default(true),
		algorithm: z.enum([
			"ed25519_raw",
			"ed25519_jws",
			"es256_jws",
			"es256k_jws",
		]).default("ed25519_raw"),
		messageMaxAgeSec: z.coerce.number().default(300),
	}).default({}),
});

export const didModule: GrantModule = {
	grants: {
		did: (deps) => createDidGrant(deps),
	},
	configSchema: didConfigSchema,
};
