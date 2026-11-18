package allow

import "testing"

func TestAllows(t *testing.T) {
	l, err := New([]string{"Gosuslugi.ru", "мвд.рф", "gov.ru"})
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{
		"gosuslugi.ru",
		"www.gosuslugi.ru",
		"esia.gosuslugi.ru.",
		"WWW.GOSUSLUGI.RU:443",
		"мвд.рф",
		"xn--b1aew.xn--p1ai",
		"digital.gov.ru",
	}
	for _, h := range ok {
		if !l.Allows(h) {
			t.Errorf("expected allow %s", h)
		}
	}
	bad := []string{
		"gosuslugi.ru.evil.com",
		"evilgosuslugi.ru",
		"notgov.ru",
		"127.0.0.1",
		"www.gosuslugi.ru:8443",
		"",
		"gosuslugi.ru/path",
	}
	for _, h := range bad {
		if l.Allows(h) {
			t.Errorf("expected deny %s", h)
		}
	}
}
