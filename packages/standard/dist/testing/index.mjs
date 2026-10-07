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
/** The SMTP mail sender's section, `standard-smtp-mail-sender`, as the package's reference.conf resolves it, with `options` laid over it. */
export function standardSmtpMailSenderConfigForTests(options = {}) {
    return {
        "standard-smtp-mail-sender": {
            port: 587,
            secure: "starttls",
            ...options,
        },
    };
}
