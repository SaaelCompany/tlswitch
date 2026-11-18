package catalog

import (
	"path/filepath"
	"testing"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/config"
)

func TestBuiltinHostIsAllowed(t *testing.T) {
	list, err := allow.New([]string{"gov.ru"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "sites.json"), list, []config.PortalSite{
		{Title: "ФРМО", URL: "https://nr.egisz.rosminzdrav.ru"},
	}); err != nil {
		t.Fatal(err)
	}
	if !list.Allows("nr.egisz.rosminzdrav.ru") {
		t.Fatal("portal host was not allowed")
	}
	if list.Allows("other.rosminzdrav.ru") {
		t.Fatal("a neighbouring host was opened")
	}
}

func TestAddRemembersHostAndSurvivesReload(t *testing.T) {
	list, err := allow.New([]string{"gosuslugi.ru"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c, err := Open(filepath.Join(dir, "sites.json"), list, []config.PortalSite{
		{Title: "Госуслуги", URL: "https://www.gosuslugi.ru"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add("lk.example.ru/cabinet", "Кабинет"); err != nil {
		t.Fatal(err)
	}
	if !list.Allows("lk.example.ru") {
		t.Fatal("host was not allowed")
	}
	if list.Allows("other.example.ru") {
		t.Fatal("sibling host should stay closed")
	}
	again, err := Open(filepath.Join(dir, "sites.json"), list, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range again.Sites() {
		if s.Title == "Кабинет" && s.Custom {
			found = true
		}
	}
	if !found {
		t.Fatal("saved site missing")
	}
	if err := c.Remove("https://lk.example.ru/cabinet"); err != nil {
		t.Fatal(err)
	}
	if list.Allows("lk.example.ru") {
		t.Fatal("removed host still allowed")
	}
	if !list.Allows("www.gosuslugi.ru") {
		t.Fatal("builtin suffix was removed")
	}
}
