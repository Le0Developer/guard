package app

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *App) mfaManage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireUser(w, r); !ok {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/keys/start") {
		a.mfaEnrollStart(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/keys/finish") {
		a.mfaEnrollFinish(w, r)
		return
	}
	ctx := r.Context()
	var c mfaContext
	var setup map[string]any
	var codes []string
	invalidCode := false
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		var e error
		c, e = a.mfaContext(r, q)
		if e != nil {
			return e
		}
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/totp"):
			name, e := mfaName(r.FormValue("name"))
			if e != nil {
				return e
			}
			secretBytes := make([]byte, 20)
			if _, e = rand.Read(secretBytes); e != nil {
				return e
			}
			secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
			encrypted, e := a.mfaSeal(c.Target.ID, secret)
			if e != nil {
				return e
			}
			ticket, e := a.mfaTicket(ctx, q, c.Target, c.Actor.ID, &c.Session.ID, nil, "totp-enroll", mfaState{Name: name, Secret: encrypted})
			if e != nil {
				return e
			}
			uri := "otpauth://totp/" + url.PathEscape(strings.ReplaceAll(a.Config.brandName(), ":", "_")+":"+strings.ReplaceAll(c.Target.Username, ":", "_")) + "?secret=" + secret + "&issuer=" + url.QueryEscape(strings.ReplaceAll(a.Config.brandName(), ":", "_")) + "&algorithm=SHA1&digits=6&period=30"
			qr, e := mfaQRCode(uri)
			if e != nil {
				return e
			}
			setup = map[string]any{"Base": c.Base, "Secret": secret, "URI": template.URL(uri), "QRCode": qr, "Ticket": ticket}
			return nil
		case strings.HasSuffix(path, "/totp/confirm"):
			ticket, u, e := a.mfaLoad(ctx, q, r.FormValue("ceremony"), "totp-enroll")
			if e != nil {
				return e
			}
			if !c.bound(ticket) {
				return errMFA
			}
			var s mfaState
			if e = json.Unmarshal(ticket.State, &s); e != nil {
				return e
			}
			secret, e := a.mfaOpen(u.ID, s.Secret)
			if e != nil {
				return e
			}
			step, ok := mfaStep(secret, r.FormValue("code"), -1)
			if !ok {
				invalidCode = true
				return a.mfaFailure(ctx, q, ticket, u)
			}
			_, e = q.CreateTotpAuthenticator(ctx, db.CreateTotpAuthenticatorParams{UserID: u.ID, Name: s.Name, Secret: s.Secret, LastStep: step, LastUsedAt: ptr(time.Now())})
			if e != nil {
				return e
			}
			return a.mfaChanged(ctx, q, u, c.Actor.ID, c.keep(), "Added authenticator")
		case strings.HasSuffix(path, "/backup-codes"):
			if r.FormValue("confirm") != "generate" {
				return errors.New("Confirm replacement of backup codes.")
			}
			fs, e := q.TotpAuthenticatorsByUserId(ctx, c.Target.ID)
			if e != nil {
				return e
			}
			ks, e := q.WebauthnCredentialsByUserId(ctx, c.Target.ID)
			if e != nil {
				return e
			}
			if len(fs)+len(ks) == 0 {
				return errors.New("Add an MFA method first.")
			}
			if e = q.MFADeleteRecovery(ctx, c.Target.ID); e != nil {
				return e
			}
			for range 10 {
				raw := make([]byte, 16)
				if _, e = rand.Read(raw); e != nil {
					return e
				}
				text := hex.EncodeToString(raw)
				code := text[:8] + "-" + text[8:16] + "-" + text[16:24] + "-" + text[24:]
				_, e = q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{UserID: c.Target.ID, Hash: mfaRecoveryHash(c.Target.ID, code)})
				if e != nil {
					return e
				}
				codes = append(codes, code)
			}
			return a.mfaChanged(ctx, q, c.Target, c.Actor.ID, c.keep(), "Replaced recovery codes")
		case strings.HasSuffix(path, "/reset"):
			if r.FormValue("confirm") != "reset" {
				return errors.New("Confirm the MFA reset.")
			}
			if e = q.MFADeleteTOTP(ctx, c.Target.ID); e != nil {
				return e
			}
			if e = q.MFADeleteKeys(ctx, c.Target.ID); e != nil {
				return e
			}
			if e = q.MFADeleteRecovery(ctx, c.Target.ID); e != nil {
				return e
			}
			return a.mfaChanged(ctx, q, c.Target, c.Actor.ID, 0, "Reset MFA")
		default:
			n, e := strconv.ParseInt(r.PathValue("method_id"), 10, 64)
			if e != nil || n <= 0 {
				return errMFA
			}
			rename := strings.HasSuffix(path, "/rename")
			if !rename {
				fs, e := q.TotpAuthenticatorsByUserId(ctx, c.Target.ID)
				if e != nil {
					return e
				}
				ks, e := q.WebauthnCredentialsByUserId(ctx, c.Target.ID)
				if e != nil {
					return e
				}
				if len(fs)+len(ks) <= 1 {
					return errors.New("Use Reset MFA to remove the final method and backup codes.")
				}
			}
			name := ""
			if rename {
				name, e = mfaName(r.FormValue("name"))
				if e != nil {
					return e
				}
			}
			switch r.PathValue("kind") {
			case "totp":
				f, e := q.LockTotpAuthenticator(ctx, ids.TotpAuthenticatorID(n))
				if e != nil {
					return e
				}
				if f.UserID != c.Target.ID {
					return errMFA
				}
				if rename {
					_, e = q.UpdateTotpAuthenticator(ctx, db.UpdateTotpAuthenticatorParams{ID: f.ID, UserID: f.UserID, Name: name, Secret: f.Secret, LastStep: f.LastStep, LastUsedAt: f.LastUsedAt})
				} else {
					e = q.DeleteTotpAuthenticator(ctx, f.ID)
				}
				if e != nil {
					return e
				}
			case "webauthn":
				f, e := q.LockWebauthnCredential(ctx, ids.WebauthnCredentialID(n))
				if e != nil {
					return e
				}
				if f.UserID != c.Target.ID {
					return errMFA
				}
				if rename {
					_, e = q.UpdateWebauthnCredential(ctx, db.UpdateWebauthnCredentialParams{ID: f.ID, UserID: f.UserID, CredentialID: f.CredentialID, Name: name, Credential: f.Credential, SignCount: f.SignCount, LastUsedAt: f.LastUsedAt})
				} else {
					e = q.DeleteWebauthnCredential(ctx, f.ID)
				}
				if e != nil {
					return e
				}
			default:
				return errMFA
			}
			if rename {
				return a.audit(ctx, q, c.Actor.ID, "Renamed MFA method", map[string]any{"subject_id": c.Target.ID, "kind": r.PathValue("kind"), "method_id": n})
			}
			fs, e := q.TotpAuthenticatorsByUserId(ctx, c.Target.ID)
			if e != nil {
				return e
			}
			ks, e := q.WebauthnCredentialsByUserId(ctx, c.Target.ID)
			if e != nil {
				return e
			}
			if len(fs)+len(ks) == 0 {
				if e = q.MFADeleteRecovery(ctx, c.Target.ID); e != nil {
					return e
				}
			}
			return a.mfaChanged(ctx, q, c.Target, c.Actor.ID, c.keep(), "Removed MFA method")
		}
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	if invalidCode {
		a.mfaError(w, r, errors.New("Invalid authenticator code."))
		return
	}
	if setup != nil {
		a.page(w, r, "Set up authenticator", totpSetupTemplate, setup)
		return
	}
	if codes != nil {
		a.page(w, r, "Backup codes", backupCodesTemplate, map[string]any{"Codes": codes, "Base": c.Base})
		return
	}
	destination := c.Base
	if strings.HasSuffix(r.URL.Path, "/reset") && c.Target.ID == c.Actor.ID {
		destination = "/login"
	}
	http.Redirect(w, r, destination, 303)
}
