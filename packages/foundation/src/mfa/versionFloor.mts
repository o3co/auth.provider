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
 * A floor under the versions the Store answers for a factor record, kept
 * outside the Store in the provider's `ReplaySeenSet`: within the horizon
 * after a write through this provider, a record is admitted only at the
 * version last written. A Store that lost or rolled back that write would
 * answer an older record, whose sealed data still opens — a used TOTP step,
 * a spent recovery code — and nothing in the record can tell.
 *
 * Guarantees: a record written at `v` is refused at any version but `v` for
 * at least {@link MFA_FACTOR_VERSION_FLOOR_HORIZON_MS} after the write, on any
 * replica whose clock is within that of the writer's, and every version is
 * admitted again at most two horizons after the last write; a key carries
 * neither the subject nor the factor id; a write or a read the seen-set
 * cannot make throws. Marks: `written` for each version written, and
 * `recent` for each record written in a horizon-long bucket, set on the
 * write's bucket and both of its neighbours.
 */

import { createHash } from "node:crypto";
import type { ReplaySeenSet } from "@o3co/auth-provider-core";

/**
 * How long the floor holds after a write: longer than any TOTP code can be
 * answered again (five steps of 120 seconds at most).
 */
export const MFA_FACTOR_VERSION_FLOOR_HORIZON_MS = 30 * 60 * 1000;

/** The seen-set scope the floor's marks are kept under. */
export const MFA_FACTOR_VERSION_FLOOR_SCOPE = "mfa-factor-version-floor";

export interface MfaFactorVersionFloor {
	/** Records that an update of `(subject, id)` wrote `version`. */
	wrote(subject: string, id: string, version: number): Promise<void>;
	/** Whether a record of `(subject, id)` answered at `version` may be read. */
	admits(subject: string, id: string, version: number): Promise<boolean>;
}

export interface MfaFactorVersionFloorOptions {
	/** The clock buckets are read on. Default `Date.now`. */
	readonly now?: () => number;
}

/** Each part after its UTF-8 length, so no part can absorb its neighbour. */
const lengthPrefixed = (parts: readonly string[]): Buffer =>
	Buffer.concat(
		parts.flatMap((part) => {
			const bytes = Buffer.from(part, "utf8");
			const length = Buffer.alloc(4);
			length.writeUInt32BE(bytes.length);
			return [length, bytes];
		}),
	);

/** The record's key: a digest of the subject and the factor id, which it names neither. */
const recordKey = (subject: string, id: string): string =>
	createHash("sha256")
		.update(lengthPrefixed([subject, id]))
		.digest("base64url");

/** The floor, kept in `seen`. */
export function createMfaFactorVersionFloor(
	seen: ReplaySeenSet,
	{ now = Date.now }: MfaFactorVersionFloorOptions = {},
): MfaFactorVersionFloor {
	const H = MFA_FACTOR_VERSION_FLOOR_HORIZON_MS;
	const scope = MFA_FACTOR_VERSION_FLOOR_SCOPE;
	const written = (record: string, version: number) => `written:${record}:${version}`;
	const recent = (record: string, bucket: number) => `recent:${record}:${bucket}`;

	return Object.freeze({
		async wrote(subject: string, id: string, version: number): Promise<void> {
			const record = recordKey(subject, id);
			const bucket = Math.floor(now() / H);
			// The version first: a `recent` mark without its version's would
			// refuse the record's current version until the mark expires.
			await seen.markSeen(scope, written(record, version), (bucket + 3) * H);
			await Promise.all(
				[bucket - 1, bucket, bucket + 1].map((near) =>
					seen.markSeen(scope, recent(record, near), (bucket + 2) * H),
				),
			);
		},

		async admits(subject: string, id: string, version: number): Promise<boolean> {
			const record = recordKey(subject, id);
			if (!(await seen.contains(scope, recent(record, Math.floor(now() / H))))) return true;
			const [isWritten, isSuperseded] = await Promise.all([
				seen.contains(scope, written(record, version)),
				seen.contains(scope, written(record, version + 1)),
			]);
			return isWritten && !isSuperseded;
		},
	});
}
