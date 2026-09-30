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
 * `smtpMailSenderModule`: the SMTP mail sender's module (the MFA ADR's D5),
 * named after its section, `smtp-mail-sender`, which boot parses with the
 * module's schema before any factory runs. The sender is not built: the
 * module provides nothing, so a composition that needs a `mailSender` is
 * refused for want of one. Stateless.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { smtpMailSenderConfigSchema } from "./config.mjs";

/** The SMTP mail sender's module: its section; no sender yet. */
export const smtpMailSenderModule = defineModule({
	name: "smtp-mail-sender",
	section: {
		schema: smtpMailSenderConfigSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
	},
});
