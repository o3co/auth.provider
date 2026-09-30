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
 * `@o3co/auth-provider-standard/testing`: the builders a test assembles this
 * package's configuration with, so no test writes a section of this
 * package's by hand. Each is a configuration fragment at its section's name,
 * with the reference defaults and the keys a test lays over them. Test code
 * imports it; production code never does.
 */

import type { STANDARD_SMTP_SECURE_MODES } from "../mail/smtp/config.mjs";

/** What {@link standardSmtpMailSenderConfigForTests} lays over the reference defaults. */
export interface StandardSmtpMailSenderConfigForTestsOptions {
	readonly host?: string;
	readonly port?: number;
	readonly secure?: (typeof STANDARD_SMTP_SECURE_MODES)[number];
	readonly user?: string;
	readonly password?: string;
	readonly from?: string;
}

/** The SMTP mail sender's section, `standard-smtp-mail-sender`, as the package's reference.conf resolves it, with `options` laid over it. */
export function standardSmtpMailSenderConfigForTests(
	options: StandardSmtpMailSenderConfigForTestsOptions = {},
) {
	return {
		"standard-smtp-mail-sender": {
			port: 587,
			secure: "starttls" as (typeof STANDARD_SMTP_SECURE_MODES)[number],
			...options,
		},
	};
}
