# Token introspection implementation

`POST /oauth2/introspect` accepts form-encoded requests authenticated with the existing confidential OIDC client Basic or POST credentials. It rejects duplicate parameters, URL query parameters, malformed forms, missing tokens and tokens longer than 512 bytes. The endpoint sets no-store/no-cache and does not enable CORS.

Client authentication takes the existing client row lock inside a transaction, serializing checks against OAuth rotation/revocation. Both opaque access and refresh token hashes are searched regardless of the supplied hint. Only the authenticated client's tokens can be active. Checks include revocation, the appropriate token lifetime, current Guard session, account state and current client access rules. Unknown, revoked, expired and unauthorized tokens return only `{"active":false}`. Database errors return 503, never inactive. Active responses contain client ID, subject, username, scope, expiry, creation time and issuer; only access tokens include `token_type: Bearer`. JWT ID tokens are not verified or accepted as credentials.

The endpoint uses the existing access journal with buffered responses, so configured journal failures discard active responses. No request token, credential, hash or another client's metadata is included in journal data.

Tests were written before the handler (initial compilation failed on the absent registration method). The first real PostgreSQL run passed active access/refresh handling, wrong hints, rotation/revocation, unknown/cross-client tokens and malformed/authentication requests. Expanded tests additionally cover session deletion, disabled users, access rule changes, access and refresh expiry, unavailable database and failed journal writes. Final verification is recorded with the completed task.

Verification: all `TestIntrospection*` tests passed against the configured real PostgreSQL database, including journal failure. The verification command included all app package Go files except the concurrently authored `backchannel_test.go`, which currently requires an unfinished `deliverLogoutBatch` method. Root owns the full package/suite rerun after that implementation lands.
