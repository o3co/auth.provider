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
/** The development sender: every send logged, and answered delivered. */
export function createStandardDevelopmentMailSender(options) {
    const { logger } = options;
    return {
        kind: "standard-development",
        async send(mail) {
            logger.info({ purpose: mail.purpose, code: mail.code }, "mail_code_issued");
            return { outcome: "delivered" };
        },
    };
}
