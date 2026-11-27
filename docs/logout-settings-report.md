# Client logout configuration

Implemented optional back-channel logout URI and session-required settings in the
admin client form. Both create and update save these fields in the existing
admin mutation transaction. Generic client updates preserve them during secret
rotation. Saving a ForwardAuth client clears both fields, including when switching
from OIDC with existing settings.

`validateLogoutURI` is shared by the form and delivery worker. It allows an empty
setting or an absolute HTTPS URL, with HTTP limited to localhost and parsed
loopback IP addresses. Credentials, fragment markers, wildcards, whitespace, backslashes, control
characters and values longer than 2048 bytes are rejected. No dependencies were
added.

The form explains that applications must verify the logout JWT and terminate
their own session. README documents introspection authentication, client-scoped
access/refresh validation, bounded polling caches, discovery, logout JWT
validation/replay checks and delivery semantics.

Verification: the new persistence test failed before implementation because
settings were absent after client creation. Invalid URL tests separately failed
because unsafe URLs were accepted. Additional tests demonstrated that raw
whitespace, backslashes, empty explicit ports and numeric ports outside 1–65535
were accepted before validation was tightened. All these regression cases now
pass, together with the PostgreSQL-backed admin persistence, secret rotation and
ForwardAuth switch checks. The focused package run includes all package files;
the delivery worker is now present and the package compiles normally.

Final integrated `go test ./...` passed: 90 tests, zero failures, using the
configured local PostgreSQL database.
