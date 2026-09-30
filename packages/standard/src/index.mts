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

// @o3co/auth-provider-standard — standard, replaceable implementations of
// the duties outside the provider, each behind a port core declares. It
// depends on core alone.

export {
	type StandardDevelopmentMailSenderModuleOptions,
	standardDevelopmentMailSenderModule,
} from "./mail/development/module.mjs";
// The mail senders (core's `MailSender`, the `mailSender` slot): the text
// each purpose is rendered as, the SMTP sender's module and the schema of
// its section, `standard-smtp-mail-sender`, and the development sender.
export {
	createStandardDevelopmentMailSender,
	type StandardDevelopmentMailSenderOptions,
} from "./mail/development/sender.mjs";
export { type RenderedMail, renderStandardMail } from "./mail/render.mjs";
export {
	type StandardSmtpMailSenderSettings,
	standardSmtpMailSenderConfigSchema,
} from "./mail/smtp/config.mjs";
export { standardSmtpMailSenderModule } from "./mail/smtp/module.mjs";
