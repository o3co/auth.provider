# answer

Internal module of `redis`: a store script's answer read as data.

## Responsibilities
- Turns what a script answers back into the store's data: its numbers, and the lists cjson writes as objects.

## Not here
- Running a script, and which server answered: the package's.

## Offers
- `numbers` (a parsed answer): the answer with its times, counts and times left as numbers, or unavailable.
- `list` (a value cjson wrote, its count): the list it stands for.

## Invariants
- A time, a count or a time left is a whole number, written as a string of digits or as a number; anything else, a fraction, an exponent or a value past what a number holds exactly among them, makes the answer unavailable, never read as one. One that is absent or null is left so.

## Depends on
- `kernel` (unavailable).
