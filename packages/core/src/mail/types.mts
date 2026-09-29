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
 * The `MailSender` port and its `mailSender` slot: how MFA one-time codes and
 * security notices leave the provider (ADR 2026-09-25-multi-factor-authentication).
 * In core so the SMTP package and the MFA package need not depend on each
 * other. The consumer renders the message; a custom sender implements `send`
 * only. Types only; this directory is a leaf.
 */

/** A rendered message: one recipient, a subject and plain text. */
export interface MailMessage {
	readonly to: string;
	readonly subject: string;
	readonly text: string;
}

export interface MailSender {
	readonly kind: string;
	/**
	 * Resolves when the relay accepted the message; rejects on anything else.
	 * A rejection is never "sent": the caller answers `503` and logs the
	 * reason, never the address or the message.
	 */
	send(message: MailMessage): Promise<void>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** Where MFA codes and notices are delivered. */
		readonly mailSender?: MailSender;
	}
}
