package app

import (
	"encoding/json"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"math"
	"net/http"
)

type adminJournalRow struct{ ID, Time, Actor, Client, Session, Source, Action, Data, Delivery string }

func adminCursor[T ~int64](r *http.Request) (T, error) {
	if s := r.URL.Query().Get("before"); s != "" {
		v, e := adminID[T](s)
		if e != nil {
			return 0, adminInvalid("Invalid page cursor.")
		}
		return v, nil
	}
	return T(math.MaxInt64), nil
}
func (a *App) adminAudit(w http.ResponseWriter, r *http.Request, _ *identity) error {
	before, e := adminCursor[ids.AuditLogID](r)
	if e != nil {
		return e
	}
	logs, e := a.Q.AdminAuditPage(r.Context(), before)
	if e != nil {
		return e
	}
	more := len(logs) > 100
	if more {
		logs = logs[:100]
	}
	rows := []adminJournalRow{}
	actors := map[ids.UserID]string{}
	for _, log := range logs {
		actor, ok := actors[log.UserID]
		if !ok {
			u, e := a.Q.GetUser(r.Context(), log.UserID)
			if e != nil && !notFound(e) {
				return e
			}
			actor = fmt.Sprintf("%s (#%d)", u.Username, log.UserID)
			actors[log.UserID] = actor
		}
		rows = append(rows, adminJournalRow{ID: fmt.Sprint(log.ID), Time: log.CreatedAt.Format("2006-01-02 15:04:05Z07:00"), Actor: actor, Action: adminAuditLabel(log.Event, log.Data), Data: adminPretty(log.Data)})
	}
	next := ""
	if more {
		next = "/admin/audit?before=" + rows[len(rows)-1].ID
	}
	a.page(w, r, "Audit log", adminJournalTemplate, map[string]any{"Rows": rows, "Next": next})
	return nil
}
func adminPretty(raw []byte) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return string(raw)
	}
	return string(b)
}
func (a *App) adminAccess(w http.ResponseWriter, r *http.Request, _ *identity) error {
	before, e := adminCursor[ids.AccessLogID](r)
	if e != nil {
		return e
	}
	params := r.URL.Query()
	var cid ids.ClientID
	var sid *ids.SessionID
	if raw := params.Get("client_id"); raw != "" {
		v, e := adminID[ids.ClientID](raw)
		if e != nil {
			return adminInvalid("Invalid client ID.")
		}
		cid = v
	}
	if raw := params.Get("session_id"); raw != "" {
		v, e := adminID[ids.SessionID](raw)
		if e != nil {
			return adminInvalid("Invalid session ID.")
		}
		sid = &v
	}
	source := params.Get("source")
	if source != "" && source != "request" && source != "application" && source != "configuration" {
		return adminInvalid("Invalid event source.")
	}
	logs, e := a.Q.AdminAccessPage(r.Context(), db.AdminAccessPageParams{BeforeID: before, HasClient: cid != 0, ClientID: cid, HasSession: sid != nil, SessionID: sid, SourceFilter: source})
	if e != nil {
		return e
	}
	more := len(logs) > 100
	if more {
		logs = logs[:100]
	}
	rows := []adminJournalRow{}
	clients, e := a.Q.ListClients(r.Context())
	if e != nil {
		return e
	}
	names := map[ids.ClientID]string{}
	for _, c := range clients {
		names[c.ID] = c.Name
	}
	counts, e := a.Q.AdminDeliveryCounts(r.Context())
	if e != nil {
		return e
	}
	for _, log := range logs {
		state := ""
		delivery, err := a.Q.GetAccessLogDelivery(r.Context(), log.ID)
		if err != nil && !notFound(err) {
			return err
		}
		if err == nil {
			switch {
			case delivery.DeliveredAt != nil:
				state = "Delivered"
			case delivery.LastError != "":
				state = fmt.Sprintf("Retrying (%d attempts): %s", delivery.Attempts, delivery.LastError)
			default:
				state = "Pending"
			}
		}
		if state == "" {
			state = "Stored locally"
			if a.Config.ExportURL != "" {
				state = "Pending"
			}
		}
		actor, session := "—", "—"
		if log.UserID != nil {
			actor = fmt.Sprint(*log.UserID)
		}
		if log.SessionID != nil {
			session = fmt.Sprint(*log.SessionID)
		}
		rows = append(rows, adminJournalRow{ID: fmt.Sprint(log.ID), Time: log.CreatedAt.Format("2006-01-02 15:04:05Z07:00"), Actor: actor, Client: fmt.Sprintf("%s (#%d)", names[log.ClientID], log.ClientID), Session: session, Source: log.Source, Data: adminPretty(log.Data), Delivery: state})
	}
	next := ""
	if more {
		params.Set("before", rows[len(rows)-1].ID)
		next = "/admin/access-log?" + params.Encode()
	}
	a.page(w, r, "Access journal", adminAccessFilter+adminJournalTemplate, map[string]any{"Rows": rows, "Next": next, "Access": true, "Clients": clients, "ClientFilter": r.URL.Query().Get("client_id"), "SessionFilter": r.URL.Query().Get("session_id"), "SourceFilter": source, "Pending": counts.Pending, "Failed": counts.Failed, "Export": a.Config.ExportURL != ""})
	return nil
}

// Historical records and non-admin events retain their original labels.
func adminAuditLabel(event string, raw []byte) string {
	var data struct {
		Summary string `json:"summary"`
		Target  struct {
			Name string `json:"name"`
		} `json:"target"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Summary == "" {
		return event
	}
	if data.Target.Name != "" {
		return data.Summary + " · " + data.Target.Name
	}
	return data.Summary
}
