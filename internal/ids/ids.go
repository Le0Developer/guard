// Package ids defines distinct database identity types.
package ids

type UserID int64
type SessionID int64
type LoginSessionID int64
type GroupID int64
type ClientID int64
type ClientRedirectID int64
type AuthorizationCodeID int64
type OAuthTokenID int64
type SigningKeyID int64
type TotpAuthenticatorID int64
type WebauthnCredentialID int64
type RecoveryCodeID int64
type MfaCeremonyID int64
type ForwardAuthRequestID int64
type ForwardAuthSessionID int64
type AuditLogID int64
type AccessLogID int64

type OIDCSessionID int64
type LogoutDeliveryID int64

type UpstreamProviderID int64

type SAMLACSID int64
type SAMLSPCertificateID int64
type SAMLSigningKeyID int64
type SAMLRequestID int64
type SAMLSessionID int64
