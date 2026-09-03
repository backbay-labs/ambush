# narrative-agent-names

The agent reports status about two in-channel bots. Both names must remain
plain narrative text: neither bot may receive a `p` tag or an `@Name` wake-up.
The requesting human must still receive the callback mention. This guards the
acknowledgement and false-wake behavior in
[backbay-labs/ambush#5176](https://github.com/backbay-labs/ambush/issues/5176).
