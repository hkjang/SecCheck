package web

import (
	"testing"

	"github.com/hkjang/SecCheck/internal/mail"
)

// bellOnly are the catalogue's event types that are never mailed: a comment
// is a conversation the reader opens on their own time, and a revoked API
// key announces itself the moment the key is used.
var bellOnly = map[string]bool{"COMMENT_ADDED": true, "API_KEY_REVOKED": true}

// Every event the preference screen offers is either under one of the
// administrator's mail switches or deliberately bell-only, and every switch
// names only events the catalogue has -- a new event type has to be placed
// on one side or the other, and a renamed one cannot leave a switch pointing
// at nothing.
func TestEveryNotificationTypeIsPlacedUnderAMailSwitchOrKeptOnTheBell(t *testing.T) {
	catalogue := map[string]bool{}
	for _, event := range notificationEvents {
		catalogue[event["code"]] = true
		switch key := mail.SwitchFor(event["code"]); {
		case key == "" && !bellOnly[event["code"]]:
			t.Errorf("%s (%s) is neither under a mail switch nor listed as bell-only", event["code"], event["label"])
		case key != "" && bellOnly[event["code"]]:
			t.Errorf("%s is listed as bell-only and under %s", event["code"], key)
		}
	}
	for _, sw := range mail.Switches {
		for _, event := range sw.Events {
			if !catalogue[event] {
				t.Errorf("%s covers %s, which the notification catalogue does not have", sw.Key, event)
			}
		}
	}
	for event := range bellOnly {
		if !catalogue[event] {
			t.Errorf("bell-only names %s, which the notification catalogue does not have", event)
		}
	}
}
