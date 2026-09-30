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
 * A `MailSender` for tests: it keeps every send it delivers instead of
 * delivering it, and can stand in for a sender at a limit or a relay that is
 * down. Each instruction holds until the next.
 */

import type { MailSend, MailSender, MailSendResult } from "../mail/types.mjs";

export interface RecordingMailSender extends MailSender {
	readonly kind: "recording";
	/** Every send it delivered, oldest first, as frozen copies. */
	readonly sent: readonly MailSend[];
	/** From now on, every send answers `refused_at_limit` and keeps nothing. */
	refuseAtLimit(): void;
	/** From now on, every send rejects with `error` and keeps nothing — a relay that is down. */
	failWith(error: unknown): void;
	/** Deliver again. */
	recover(): void;
}

type Mode =
	| { readonly kind: "deliver" }
	| { readonly kind: "limit" }
	| { readonly kind: "fail"; readonly error: unknown };

export function createRecordingMailSender(): RecordingMailSender {
	let sent: readonly MailSend[] = Object.freeze([]);
	let mode: Mode = { kind: "deliver" };

	return {
		kind: "recording",
		get sent() {
			return sent;
		},
		async send(mail: MailSend): Promise<MailSendResult> {
			if (mode.kind === "fail") throw mode.error;
			if (mode.kind === "limit") return { outcome: "refused_at_limit" };
			const copy: MailSend = Object.freeze({
				purpose: mail.purpose,
				subject: mail.subject,
				to: mail.to,
				code: mail.code,
				expiresAtMs: mail.expiresAtMs,
			});
			sent = Object.freeze([...sent, copy]);
			return { outcome: "delivered" };
		},
		refuseAtLimit(): void {
			mode = { kind: "limit" };
		},
		failWith(error: unknown): void {
			mode = { kind: "fail", error };
		},
		recover(): void {
			mode = { kind: "deliver" };
		},
	};
}
