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
 * @param maxDepth total certificates to read, leaf included. A peer that
 * sends more has the remainder ignored rather than the request refused: path
 * validation bounds the chain it will accept anyway, and refusing here would
 * turn a verbose-but-valid client into an error at a layer that cannot
 * explain itself.
 */
export const peerChainFrom = (peer, maxDepth) => {
    if (!peer?.raw || peer.raw.length === 0)
        return null;
    const leafDer = new Uint8Array(peer.raw);
    const chainDer = [];
    const seen = new Set([Buffer.from(leafDer).toString("base64")]);
    let current = peer.issuerCertificate;
    while (current?.raw && current.raw.length > 0 && chainDer.length + 1 < maxDepth) {
        const der = new Uint8Array(current.raw);
        const fingerprint = Buffer.from(der).toString("base64");
        // Terminates the self-referential root, and any loop a peer constructs.
        if (seen.has(fingerprint))
            break;
        seen.add(fingerprint);
        chainDer.push(der);
        current = current.issuerCertificate;
    }
    return { leafDer, chainDer };
};
