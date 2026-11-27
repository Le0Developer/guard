ALTER TABLE upstream_providers
 ADD COLUMN configuration_mode text NOT NULL DEFAULT 'oidc_discovery' CHECK (configuration_mode IN ('oidc_discovery','oidc_manual','oauth2')),
 ADD COLUMN discovery_url text NOT NULL DEFAULT '',
 ADD COLUMN subject_field text NOT NULL DEFAULT 'sub',
 ADD COLUMN email_field text NOT NULL DEFAULT 'email',
 ADD COLUMN email_verified_field text NOT NULL DEFAULT 'email_verified',
 ADD COLUMN client_auth_method text NOT NULL DEFAULT 'client_secret_post' CHECK (client_auth_method IN ('client_secret_post','client_secret_basic'));
UPDATE upstream_providers SET discovery_url=rtrim(issuer,'/') || '/.well-known/openid-configuration';
