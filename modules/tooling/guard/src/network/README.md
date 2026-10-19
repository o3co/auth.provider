# network

Internal module of `guard`: G26, how product code may reach the network.

## Responsibilities
- Finds where a product package's shipped code reaches the network, and holds it to the words its manifest declares in `network`, each stated on its card as `` `network`: `<word>` ``.

## Not here
- Which packages reach the network: each package's own declaration, never a list here.
- Reaching the network in ways a file's syntax does not show: code run by `eval` or a `Worker`, a native addon, or a function handed in from elsewhere. Review judges those.

## Offers
- `networkRules` (G26) and `reachesOf` (a file's places that reach the network).

## Invariants
- A place reaches the network where shipped code does one of these:
  - Imports, not as a type alone, a name that opens a connection or a server from `node:http`, `node:https`, `node:net`, `node:tls`, `node:dgram` or `node:http2`, or one that asks a resolver from `node:dns` or `node:dns/promises`, or one of those modules whole. Functions that reach nothing, such as `isIP` and `BlockList`, are not counted.
  - Imports anything from `node:child_process`: a process started can reach anything.
  - Imports a network client: `ioredis`, `nodemailer`, `undici`, `ws`, `node-fetch`, `axios` or `got`.
  - Uses `fetch`, `WebSocket` or `EventSource` as a value where no declaration of the name in scope at that place hides it (one in another function does not), or as a property of `globalThis`, `global`, `self` or `window`.
  - Loads one of the modules or clients above with `import()` or `require`, as if imported whole, or loads a module named only at run time (`import()`).
- The words, and what each lets a package reach:
  - `serves-http`: `node:http`'s `createServer` and `Server`.
  - `outbound`: `node:http`'s and `node:https`'s `request` and `Agent`, `node:net`'s and `node:tls`'s `connect`, and `lookup` from `node:dns` and `node:dns/promises`.
  - `redis`: the `ioredis` client.
  - `smtp`: `node:net`'s and `node:tls`'s `connect`, and `nodemailer`.
- A place no declared word lets through is refused, as is a word guard does not know, a declared word the package reaches nothing with, and a word its card does not state. Tests, test tables and verification and assembly packages are not read.

## Depends on
- `typescript`.
