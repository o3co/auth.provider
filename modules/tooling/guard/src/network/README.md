# network

Internal module of `guard`: G26, how product code may reach the network, and G27, where a card states the server it needs.

## Responsibilities
- Finds where a product package's shipped code reaches the network, and holds it to the words its manifest declares in `network`, each stated on its card as `` `network`: `<word>` ``.

## Not here
- Which packages reach the network: each package's own declaration, never a list here.
- A form written to slip past these rules: they catch the ordinary ways our own code reaches the network, `node:child_process` included; one written to evade them is review's to catch.
- Reaching the network in ways a file's syntax does not show: code run by `eval` or a `Worker`, a native addon, a function handed in from elsewhere, the global object reached under another name, or a property named at run time. Review judges those.

## Offers
- `networkRules` (G26, G27), `helpersOf` (the plain helpers the packages' `forks` name, which the run's shared analysis reads beside the sources), `reachesIn` (a file's facts → the places it reaches the network) and `reachesOf` (a file read on its own).

## Invariants
- It reads each file's `facts` (`guard-imports`), a fork's helper's too from the same shared analysis: an import's and a re-export's bindings, a module loaded (`import()`, a loader's call, `import = require`), and a name or a property read with what it is bound to.
- A name, or the owner of a property read, counts only as a value (its role `value`: never in a type or an ambient context). So a shorthand property and a local export read the global they name, and `require` in parentheses, or a loader `createRequire` made, loads as `require` does.
- An import and a re-export are read alike: a default, taken by name or not, a namespace or `export *` binds a module whole, a name binds that name, and one binding types alone reaches nothing.
- A place reaches the network where shipped code does one of these:
  - Imports or re-exports, not as a type alone, a name that opens a connection or a server from `node:http`, `node:https`, `node:net`, `node:tls`, `node:dgram` or `node:http2`, or one that asks a resolver from `node:dns` or `node:dns/promises`, or one of those modules whole. Functions that reach nothing, such as `isIP` and `BlockList`, are not counted.
  - Imports or re-exports anything from `node:child_process`: a process started can reach anything. One starter is let through, below.
  - Imports or re-exports a network client: `ioredis`, `nodemailer`, `undici`, `ws`, `node-fetch`, `axios` or `got`.
  - Uses `fetch`, `WebSocket` or `EventSource` as a value where no declaration of the name in scope at that place hides it (one in another function does not), or as a property of `globalThis`, `global`, `self` or `window`, named by a dot or a string literal.
  - Loads one of the modules or clients above with `import()` or `require`, as if imported whole, or loads a module named only at run time, by `import()` or a loader's call, either told as `import()`.
- The words, and what each lets a package reach:
  - `serves-http`: `node:http`'s `createServer` and `Server`.
  - `outbound`: `node:http`'s and `node:https`'s `request` and `Agent`, `node:net`'s and `node:tls`'s `connect`, and `lookup` from `node:dns` and `node:dns/promises`.
  - `redis`: the `ioredis` client.
  - `smtp`: `node:net`'s and `node:tls`'s `connect`, and `nodemailer`.
- A starter and its helper are read through their facts (`fork`, `join` and `lookup` by the bindings they import and the reads of them, `process` unbound); a call named `require`, or `import()`, counts as a load whatever binds it, as the launch form's own strictness asks, beside every loader the facts read.
- A package declaring `outbound` may name in `forks` one shipped source this rule reads (the starter, a plain file, never a link) and its helper, a plain `.mjs` file beside it; `forks` naming more is refused. The starter's `node:child_process` is let through only where all of these hold; else it is refused with the condition it misses:
  - It imports `fork` alone by name and reaches `node:child_process` (under either name) no other way: no other import, no re-export, no `import()` or `require` of it, nor of a module named at run time alone.
  - It reads that binding in one call (a read in a type or a type-only export aside), and names the helper as `join(import.meta.dirname, "<helper>")` with `join` imported from `node:path`, giving it a list. Names are read by binding: one shadowing `fork`, `join` or `process` is another, and a shorthand property or an export naming `fork` is a read of it.
  - It starts it in the launch form, nothing more: `execPath` `process.execPath`, `execArgv` exactly one `--max-old-space-size=<n>`, `env` a literal of `UV_THREADPOOL_SIZE`, `LOCALDOMAIN`, `RES_OPTIONS` and `HOSTALIASES` alone, `stdio` `ignore`, `ignore`, `inherit`, `ipc`, and `serialization` `json`.
- Every starter `forks` names is held to that form, whatever its scan finds it reaches: one starting nothing as written is refused all the same.
- Every helper `forks` names is a plain `.mjs` file, else reported and never read. It imports `node:dns/promises`' `lookup` alone, by one import, and loads nothing else: no other import, no re-export, no `import()` or `require`. What it reaches counts toward the package's words.
- `redis` and `smtp` reach a server the deployment provides: a package declaring either has a `## Deployment` section on its card, stating what that server must be (G27).
- A place no declared word lets through is refused, as is a word guard does not know, a declared word the package reaches nothing with, and a word its card does not state. Only the product kinds' packages are read (common, protocol, verification and assembly are not), and in them neither tests, test tables nor a published contract test suite.

## Depends on
- `guard-imports`: each file's `facts`, and `lexicalAnalysis` for a file read alone.
- `typescript`.
