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
 * `standardSmtpMailSenderModule`: the SMTP mail sender's module, named after
 * its section, `standard-smtp-mail-sender`, which boot parses with the
 * module's schema before any factory runs. This build has no SMTP delivery:
 * the module provides no sender, so a composition that needs a `mailSender`
 * and installs only this is refused for want of one. Stateless.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { standardSmtpMailSenderConfigSchema } from "./config.mjs";

/** The SMTP mail sender's module: its section alone. */
export const standardSmtpMailSenderModule = defineModule({
	name: "standard-smtp-mail-sender",
	section: {
		schema: standardSmtpMailSenderConfigSchema,
		reference: new URL("../../../config/reference.conf", import.meta.url),
	},
});
