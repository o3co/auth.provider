/**
 * Reject a page/batch size that is not a positive integer, at construction.
 *
 * Shared rather than inlined per helper because the three sid-keyed structures
 * take the same kind of knob and the failure mode is not uniform — which makes
 * it easy to guard the one that hangs and forget the two that do not:
 *
 *   - `createRedisSidSortedSet`'s `pageSize` is a **loop step**. A value that
 *     does not advance the cursor makes `list()` repeat one command forever, on
 *     the logout path. `0` is the sharpest case: `ZRANGE key 0 -1` returns the
 *     whole set, so the short-page test that ends the walk never fires.
 *   - `createRedisSidHash`'s and `createRedisSidSet`'s `scanCount` are `HSCAN` /
 *     `SSCAN` `COUNT` hints. Those cannot hang, but Redis refuses a
 *     non-positive `COUNT`, and finding that out during a logout is no better.
 *
 * `Number.isSafeInteger` covers `NaN`, both infinities and fractional values in
 * one test; a fractional step would also drift the rank arithmetic into
 * non-integer `ZRANGE` bounds, which Redis rejects.
 */
export declare function assertPositiveInteger(value: number, label: string): void;
//# sourceMappingURL=validate.d.mts.map