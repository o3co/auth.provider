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
 * A `MailSender` for tests: it keeps every message it accepts instead of
 * delivering it, and can stand in for a relay that is down.
 */

import type { MailMessage, MailSender } from "../mail/types.mjs";

export interface RecordingMailSender extends MailSender {
	readonly kind: "recording";
	/** Every message `send` accepted, oldest first, as frozen copies. */
	readonly sent: readonly MailMessage[];
	/** From now on, every `send` rejects with `error` and records nothing — a relay that is down. */
	failWith(error: unknown): void;
	/** Accept messages again. */
	recover(): void;
}

export function createRecordingMailSender(): RecordingMailSender {
	let sent: readonly MailMessage[] = Object.freeze([]);
	let failure: { readonly error: unknown } | undefined;

	return {
		kind: "recording",
		get sent() {
			return sent;
		},
		async send(message: MailMessage): Promise<void> {
			if (failure !== undefined) throw failure.error;
			const copy = Object.freeze({ to: message.to, subject: message.subject, text: message.text });
			sent = Object.freeze([...sent, copy]);
		},
		failWith(error: unknown): void {
			failure = { error };
		},
		recover(): void {
			failure = undefined;
		},
	};
}
