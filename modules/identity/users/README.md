# users

## Responsibilities
- Owns who a user is and how they are known to be the same person: verification, links with upstream identities, and verified contacts.
- Answers from the settings' users or one contributed user ledger, and keeps links and verified contacts through its Store interfaces.

## Not here
- Steps after verification, how much of the attributes to expose, registration, password reset, when to link or verify a contact, and the proofs each feature keeps.

## Offers
- `verify` (identifier, password), `bySubject` and `byUpstream` (IdP name, upstream subject), each answering a user or none; `bySubject` and `claimedContacts` may answer unanswerable.
- `claimedContacts`, `verifiedContact` (subject, `{ kind: "email", value }`), `contactsOf`, `link` (linked, already or conflict) and `unlink` (unlinked, none or fixed).
- Extension point `ledgers`: a user ledger (verification, user by subject or unanswerable, and optionally by upstream identity), which takes the same work for an unknown identifier as for a known one; one looking users up by upstream identity has the last word there: links are neither read nor written here, and the link store, composed all the same, is never asked, so `link` answers already or conflict, and `unlink` fixed or none.
- Extension point `upstreamNames`: the IdP names a module passes to `byUpstream`, each with the issuer it stands for, one list per module; boot is refused on an empty name or issuer, and on a name standing for two issuers, within one list or across them, naming the declaring modules and never a name or an issuer.
- Operator section `registered`: `identifier`, `subject` (default the identifier), `password-hash`, `attributes`, `upstream` (each `{ idp, subject }`).
- Store interfaces for links, per upstream identity, and verified contacts, per subject, kept without end: no eviction, survives a crash and a failover, and link reads confirmed.
- `userAttribute`, typed by `UserAttributes`: the attributes users names, by OIDC claim name `email`, `email_verified`, `name`, `picture` and `groups`; a user may hold others. `isAttributeValue` (name, value): whether users takes the value. `acceptedAttributes` (values of any shape): the named ones users takes, frozen; an email's verification only beside the email. `isWellFormedSubject`: a subject's shape, 1 to 255 ASCII characters.
- `./testing`: contract tests for users, user ledgers and both Store interfaces, configuration builders, and both Store interfaces in memory.

## Invariants
- A subject is 1 to 255 ASCII characters: one outside that refuses boot in the settings (the identifier's, where `subject` is left out), is unavailable in a ledger's answer, is none when looked up without asking the ledger, and throws TypeError on `link`.
- Identifiers match exactly, never folded or trimmed, and a password as typed, with no Unicode normalization; an empty identifier or subject is none, and the ledger is not asked.
- Boot is refused on identifiers that differ only in case, Unicode normal form or surrounding whitespace, on two identifiers with one subject, on an upstream identity linked to two users, on one whose IdP name no module declares (at its `idp`), and on more than one ledger or a ledger beside `registered` users.
- Unanswerable is never read as none: a written link then is unavailable, as nothing can say who it stands for, and claimed contacts are unanswerable.
- An upstream identity matches exactly, by IdP name and whole upstream subject, never by email, is never created on the fly, and links to one subject at most, also when two ask at once.
- Only an explicit link links; unlinking removes only the subject's own link, and a written link finds its subject's user, or none where the ledger answers none for the subject: the ledger's none outweighs the link.
- A settings link wins over a written link of the same upstream identity, which stays hidden and cannot be unlinked (unlink answers fixed); taking the identity out of the settings lets the written link take effect again.
- A contact is kept once per subject by `mail`'s canonical form, as first given, up to 20, and another past them throws RangeError; an empty subject, upstream part or contact value throws TypeError.
- A claimed contact is the user's `email` attribute, as given, apart from verified contacts.
- Attribute values: `email` one mail takes that is also RFC 5322's addr-spec in ASCII (a dot-atom local part, LDH labels), `picture` an https URL that reads back as given, `email_verified` a boolean, `name` text holding more than blanks, `groups` a list of text, no text with a control or format character; another refuses boot in the settings, and from a ledger is left out, its name logged.
- A password hash is one `secret-hash` reads (bcrypt or scrypt), else boot is refused; a password over 1024 bytes is none before any computation or ledger call, and `secret-hash` decides the rest, within its assembly's `max-concurrent`.
- Each verification does the work of every kind of hash in use, so timing does not tell whether a user exists.

## Depends on
- `kernel`, `mail`, `secret-hash`

## Vocabulary
- user: a subject and frozen attributes. user ledger: the outside system that holds users.
- upstream subject: who an upstream IdP says a user is. upstream identity: an IdP's name and an upstream subject there. link: an upstream identity tied to a subject, by the settings (fixed) or written.
- verified contact: a way to reach a user that the user has shown is theirs. claimed contact: one the settings or a ledger state.
