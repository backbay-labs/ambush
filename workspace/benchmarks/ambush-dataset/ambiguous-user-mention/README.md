# ambiguous-user-mention

The channel contains two real identities with the exact same three-word display
name. Their profile `about` fields carry different routing codes. The agent must
discover the intended pubkey, notify it exactly once, never notify the twin,
and separately callback the requester. This guards the silent ambiguity family
reported in [backbay-labs/ambush#4303](https://github.com/backbay-labs/ambush/issues/4303) and
[backbay-labs/ambush#6257](https://github.com/backbay-labs/ambush/issues/6257).
