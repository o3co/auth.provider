# network

Internal module of `guard`: G26, how product code may reach the network.

## Responsibilities
- Finds where a product package's shipped code reaches the network, and holds it to the words its manifest declares in `network`, each stated on its card as `` `network`: `<word>` ``.

## Not here
- Which packages reach the network: each package's own declaration, never a list here.

## Offers
- `networkRules` (G26) and `reachesOf` (a file's places that reach the network).

## Invariants
- A place reaches the network when shipped code imports, not as a type alone, a name that opens a connection or a server from `node:http`, `node:https`, `node:net`, `node:tls`, `node:dgram` or `node:http2`; imports one of those modules whole; imports a network client (`ioredis`, `nodemailer`, `undici`, `ws`, `node-fetch`, `axios`, `got`); or calls `fetch`, `WebSocket` or `EventSource` where no local binding of the name hides it. Functions that reach nothing, such as `isIP` and `BlockList`, are not counted.
- The words, and what each lets a package reach:
  - `serves-http`: `node:http`'s `createServer` and `Server`.
  - `outbound`: `node:http`'s and `node:https`'s `request` and `Agent`, `node:net`'s and `node:tls`'s `connect`.
  - `redis`: the `ioredis` client.
  - `smtp`: `node:net`'s and `node:tls`'s `connect`, and `nodemailer`.
- A place no declared word lets through is refused, as is a word guard does not know, a declared word the package reaches nothing with, and a word its card does not state. Tests, test tables and verification and assembly packages are not read.

## Depends on
- `typescript`.
