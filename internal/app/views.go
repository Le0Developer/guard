package app

import "strings"

func adminSection(path string) string {
	if path != "/admin" && !strings.HasPrefix(path, "/admin/") {
		return ""
	}
	section := strings.Split(strings.TrimPrefix(path, "/admin"), "/")
	if len(section) < 2 || section[1] == "" {
		return "overview"
	}
	return section[1]
}

const adminNavigation = `{{define "admin-nav"}}<nav aria-label="Administration"><ul class="pagination admin-nav">
<li><a href="/admin" class="c-info {{if eq .AdminSection "overview"}}active{{end}}" aria-current="{{if eq .AdminSection "overview"}}page{{else}}false{{end}}">Overview</a></li>
<li><a href="/admin/users" class="c-info {{if eq .AdminSection "users"}}active{{end}}" aria-current="{{if eq .AdminSection "users"}}page{{else}}false{{end}}">Users</a></li>
<li><a href="/admin/groups" class="c-info {{if eq .AdminSection "groups"}}active{{end}}" aria-current="{{if eq .AdminSection "groups"}}page{{else}}false{{end}}">Groups</a></li>
<li><a href="/admin/clients" class="c-info {{if eq .AdminSection "clients"}}active{{end}}" aria-current="{{if eq .AdminSection "clients"}}page{{else}}false{{end}}">Clients</a></li>
<li><a href="/admin/providers" class="c-info {{if eq .AdminSection "providers"}}active{{end}}" aria-current="{{if eq .AdminSection "providers"}}page{{else}}false{{end}}">Login providers</a></li>
<li><a href="/admin/audit" class="c-info {{if eq .AdminSection "audit"}}active{{end}}" aria-current="{{if eq .AdminSection "audit"}}page{{else}}false{{end}}">Audit log</a></li>
<li><a href="/admin/access-log" class="c-info {{if eq .AdminSection "access-log"}}active{{end}}" aria-current="{{if eq .AdminSection "access-log"}}page{{else}}false{{end}}">Access journal</a></li>
</ul></nav><hr>{{end}}`

const mfaChallengeTemplate = `{{if .Data.HasTOTP}}<form method="post" action="/login/mfa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="method" value="totp"><label for="authenticator-code">Authenticator code</label><input id="authenticator-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus><button class="btn btn-info" type="submit">Verify code</button></form>{{end}}
{{if .Data.HasKeys}}<form method="post" action="/login/mfa/key/start" data-webauthn="authenticate" data-finish="/login/mfa/key/finish"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="btn btn-info" type="submit">Use security key</button><p role="status" aria-live="polite" data-status></p></form>{{end}}
<details><summary>Use a backup code</summary><form method="post" action="/login/mfa"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="method" value="recovery"><label for="backup-code">Backup code</label><input id="backup-code" name="code" autocomplete="off" spellcheck="false" maxlength="80" required><button class="btn btn-info" type="submit">Use backup code</button></form></details><p><a class="c-info" href="/login">Start over</a></p>`

const passwordTemplate = `{{if .Data.Error}}<div class="alert alert-error" role="alert">{{.Data.Error}}</div>{{end}}<form method="post" action="/login/password"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="login_token" value="{{.Data.Login.InternalToken}}"><label for="email">Username</label><input id="email" type="text" name="email" placeholder="Your username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required><button type="submit" class="btn btn-info">Sign in</button></form>`
