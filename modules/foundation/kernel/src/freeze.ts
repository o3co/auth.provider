/**
 * Freezes a value received from outside once, at the boundary, down to its leaves. A part already
 * frozen is still walked, since freezing reaches one level only; a part met again is passed over.
 */
export function deepFreeze<T>(value: T): T {
	freezeFrom(value, new WeakSet());
	return value;
}

function freezeFrom(value: unknown, seen: WeakSet<object>): void {
	if (value === null || typeof value !== "object" || seen.has(value)) return;
	seen.add(value);
	for (const key of Reflect.ownKeys(value)) {
		freezeFrom((value as Record<PropertyKey, unknown>)[key], seen);
	}
	Object.freeze(value);
}
