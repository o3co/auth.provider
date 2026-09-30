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
 * The development `MailSender`: it delivers nothing and writes one line at
 * info per send, `mail_code_issued`, carrying the purpose and the code and
 * nothing else of the mail, so a developer reads the code off the log. A
 * code in a log line is a secret wherever the log is read by more than the
 * developer, so its module refuses every deployment that is not one.
 */

import type { Logger, MailSend, MailSender, MailSendResult } from "@o3co/auth-provider-core";

export interface StandardDevelopmentMailSenderOptions {
	/** Where each code is written. */
	readonly logger: Logger;
}

/** The development sender: every send logged, and answered delivered. */
export function createStandardDevelopmentMailSender(
	options: StandardDevelopmentMailSenderOptions,
): MailSender {
	const { logger } = options;
	return {
		kind: "standard-development",
		async send(mail: MailSend): Promise<MailSendResult> {
			logger.info({ purpose: mail.purpose, code: mail.code }, "mail_code_issued");
			return { outcome: "delivered" };
		},
	};
}
