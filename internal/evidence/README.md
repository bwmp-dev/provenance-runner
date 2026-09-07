# Bounded secret redaction

The collector accepts the existing maximum of 64 distinct, nonempty UTF-8
secrets totaling 64 KiB. Before opening an archive it compiles a private matching
set: literal, normalized/ANSI-stripped literal, standard and URL-safe Base64
(padded and unpadded), and lower/upper hexadecimal of the original bytes.
Empty normalized variants and duplicates are omitted. No recursive, percent,
hash, arbitrary encoding or partial-exfiltration detection is promised.

Expansion fails closed above 512 patterns, 768 KiB combined pattern bytes or
128 KiB per pattern. These limits admit every previously valid raw configuration.
The sparse failure-link automaton has at most one node per pattern byte plus its
root, and one edge per non-root node. Streaming holds at most 128 KiB of bytes;
overlapping match intervals are merged before emission. Transition searches have
at most 256 edges, with amortized linear failure-link traversal. Neither pattern
values nor the compiled automaton are serialized. Replacement markers are output,
not fed back into matching. Adjacent/overlapping matches form one redacted span.

Raw output is normalized, ANSI-stripped, matched, then line/total-limited. Live
and compressed complete logs share those bytes and redacted flags. Controlled
structured stdout prefixes are recognized before matching: JSON is decoded and
its string values sanitized, rather than replacing bytes in JSON syntax.
The direct RecordEvent boundary uses the same sanitization. With secrets present,
duplicate keys, keys or event kinds requiring sanitization, excessive nesting
(over 128 levels), and post-sanitization size overflow drop the event with a fixed
diagnostic. Keys are never silently renamed or merged. JSON numbers retain their
lexical precision. With no secrets, direct event behavior is unchanged.

The matching set cannot establish credential delivery, custody, injection,
destruction, or exclusion from other subsystems. Tests are synthetic and do not
execute hostile artifacts or prove execution isolation.
