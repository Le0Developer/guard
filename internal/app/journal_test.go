package app

import (
	"strings"
	"testing"
)

func TestReportRejectsSecretsAndNestedMetadata(t *testing.T) {
	for _, metadata := range []map[string]any{{"api_key": "x"}, {"password": "x"}, {"user_id": 5}, {"nested": map[string]any{"x": true}}} {
		v := reportInput{ReportID: "11111111-1111-4111-8111-111111111111", Event: "file.saved", Outcome: "success", Metadata: metadata}
		if validateReport(&v) == nil {
			t.Fatalf("accepted %#v", metadata)
		}
	}
}
func TestReportRedactsResourceQuery(t *testing.T) {
	v := reportInput{ReportID: "11111111-1111-4111-8111-111111111111", Event: "file.saved", Outcome: "success", Resource: "https://example.com/file?token=secret#x", Metadata: map[string]any{"url": "https://example.com/file?x=secret"}}
	if err := validateReport(&v); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.Resource, "secret") || v.Metadata["url"] != "https://example.com/file" {
		t.Fatal("leaked query")
	}
}
