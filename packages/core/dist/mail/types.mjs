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
 * The `MailSender` port and its `mailSender` slot: how a one-time code the
 * provider issued leaves it (ADR 2026-09-25-multi-factor-authentication).
 * The provider hands a sender what a mail means and nothing rendered;
 * rendering (subject line, body, language), delivery and any limit on
 * sending are the sender's. In core so a sender's package and the MFA
 * package need not depend on each other. A leaf: it imports nothing.
 */
/** What a mail is for: a closed list, each a code the provider issued. */
export const MAIL_PURPOSES = Object.freeze([
    "login_code",
    "account_email_proof",
    "email_factor_enrollment",
]);
