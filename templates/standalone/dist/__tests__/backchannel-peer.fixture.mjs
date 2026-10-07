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
 * A relying party's back-channel logout endpoint on loopback, for the
 * template's tests: it answers every POST with one status and keeps each
 * `logout_token` it was sent. The composition reaches it only with its host
 * in `core.outbound.internalHosts` (`withLoopbackRelyingParties`).
 */
import { createServer } from "node:http";
import { withOutbound } from "@o3co/auth-provider-core/testing";
/** A loopback back-channel endpoint answering `status` to every POST. */
export async function backchannelPeer(status = 200) {
    const tokens = [];
    const server = createServer((req, res) => {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
            body += chunk;
        });
        req.on("end", () => {
            const token = new URLSearchParams(body).get("logout_token");
            if (token !== null)
                tokens.push(token);
            res.writeHead(status);
            res.end();
        });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    return {
        uri: `http://127.0.0.1:${port}/logout`,
        tokens,
        close: () => new Promise((resolve) => server.close(() => resolve())),
    };
}
/** `config` with loopback listed in `core.outbound.internalHosts`, so a `BackchannelPeer` is reachable. */
export const withLoopbackRelyingParties = (config) => withOutbound(config, { internalHosts: ["127.0.0.1"] });
