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
 * What the package's store modules share of their own sections: the file that
 * holds their defaults, and the shape of a section that is one key prefix.
 */

import { z } from "zod";

/**
 * The package's `config/reference.conf`, which every store module declares as
 * its section's reference: a new `URL` on each call, so a change made through
 * one answer reaches no manifest.
 */
export function redisReference(): URL {
	return new URL("../../config/reference.conf", import.meta.url);
}

/** A store's section that holds its key namespace alone: strict, `keyPrefix` defaulting to `keyPrefix`. */
export const keyPrefixSection = (keyPrefix: string) =>
	z
		.object({ keyPrefix: z.string().default(keyPrefix) })
		.strict()
		.default(() => ({ keyPrefix }));
