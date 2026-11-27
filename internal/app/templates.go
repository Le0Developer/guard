package app

import _ "embed"

// Templates are embedded so the binary needs no external template directory.

//go:embed templates/admin-access-filter.html
var adminAccessFilter string

//go:embed templates/admin-client.html
var adminClientTemplate string

//go:embed templates/admin-csrf.html
var adminCSRF string

//go:embed templates/admin-delete.html
var adminDeleteTemplate string

//go:embed templates/admin-group.html
var adminGroupTemplate string

//go:embed templates/admin-journal.html
var adminJournalTemplate string

//go:embed templates/admin-list.html
var adminListTemplate string

//go:embed templates/admin-navigation.html
var adminNavigation string

//go:embed templates/admin-overview.html
var adminOverviewTemplate string

//go:embed templates/admin-upstream-delete.html
var adminUpstreamDeleteTemplate string

//go:embed templates/admin-upstream-list.html
var adminUpstreamListTemplate string

//go:embed templates/admin-upstream.html
var adminUpstreamTemplate string

//go:embed templates/admin-user-action.html
var adminUserActionTemplate string

//go:embed templates/admin-user.html
var adminUserTemplate string

//go:embed templates/backup-codes.html
var backupCodesTemplate string

//go:embed templates/home.html
var homeTemplate string

//go:embed templates/layout.html
var layout string

//go:embed templates/login-choices.html
var loginChoicesTemplate string

//go:embed templates/mfa-challenge.html
var mfaChallengeTemplate string

//go:embed templates/mfa-management.html
var mfaManagementTemplate string

//go:embed templates/password.html
var passwordTemplate string

//go:embed templates/totp-setup.html
var totpSetupTemplate string

//go:embed templates/admin-scim.html
var adminSCIMTemplate string

//go:embed templates/userinfo-simulator.html
var userinfoSimulatorTemplate string

//go:embed templates/admin-saml.html
var adminSAMLTemplate string

//go:embed templates/password-reset.html
var passwordResetTemplate string
