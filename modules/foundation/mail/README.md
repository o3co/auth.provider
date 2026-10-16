# mail

## Responsibilities
- Owns the contract for sending mail: the sending side gives a purpose, one address, values, and optionally a locale and an expiry.
- Collects the purposes sending sides declare and the templates (wording per purpose); refuses boot when a declared purpose has no template.
- Prepares each message for every sender: copies and checks it, renders it, checks the rendered result.
- Holds the address rule, a plain-text template part, and the logging-only sender.

## Not here
- The list of purposes and what they mean: the sending side's vocabulary.
- Any wording: templates, contributed apart.
- Delivery over a network, and its limits: the sender (an adapter).

## Offers
- `mail` contract: send (purpose, to, values, locale, expiry) → sent / limited.
- Purpose declarations (`mailPurposes`) and templates (`mailTemplates`: values, locale → subject, text), both keyed by purpose. A deployment changes the wording by replacing the module that contributes the template.
- `isAddress`: whether a string is one address mail takes; a sender checks its own configured addresses by it.
- `canonicalAddress`: an address in one form to compare by, the domain in IDNA's ASCII form, lowercase, the local part as given.
- `plainText`: one wording (English by default) for every locale, `{name}` replaced by that value as it is.
- `preparer`, for senders: called at build, it gives the function that turns a message into what may be sent, or refuses.
- Composition definition: the logging-only sender. It logs the purpose, a per-process keyed hash of the address, and the value names.
- Operator section (logging-only sender): `accept-unsent`, default false; set true to accept that nothing is sent.
- Contract tests, the module they compose with, and test configuration builders (`./testing`). A sender's harness may make its remote side answer with a limit or fail, saying words no failure may carry.

## Invariants
- One address per send; anything else (a list, a line break, a display name) is a TypeError.
- An address is at most 254 bytes in UTF-8 and holds no space, control or format character, route operator (`%`, `!`) or encoded word, else a TypeError. Letters beyond ASCII are allowed.
- Its domain reads one way, else a TypeError: IDNA's ASCII form of it is letters, digits, hyphens and dots, each `xn--` label in it decodes to other letters and encodes back to itself, and the domain is that form or its Unicode form, case aside.
- Values that are not a plain object of strings, a locale that is not a string, and an undeclared purpose are TypeErrors.
- A template whose subject is not one line, or whose text holds control characters other than line feed and tab, is a TypeError.
- A message whose expiry has come is unavailable and is not sent.
- Failures are unavailable or limited, never with the remote side's words.
- The plain-text part refuses a missing value and a value that breaks a line, and never reads a placeholder inside a value.
- The logging-only sender refuses boot unless `accept-unsent` is set, is not safe on multiple instances, and logs no address and no value.

## Data
- None stored; the logging-only sender's hash key lives for the process.

## Depends on
- `kernel`

## Vocabulary
- purpose: a name the sending side gives a kind of message; templates are chosen by it.
- template: the wording of one purpose, contributed apart from the sending side so a deployment can replace it.
- sender: the implementation of the contract that delivers.
