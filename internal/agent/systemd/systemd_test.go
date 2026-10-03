package systemd

import "testing"

func TestStatusOf(t *testing.T) {
	cases := []struct{ load, active, want string }{
		{"loaded", "active", "running"},
		{"loaded", "reloading", "running"},
		{"loaded", "activating", "running"},
		{"loaded", "failed", "failed"},
		{"loaded", "inactive", "stopped"},
		{"loaded", "deactivating", "stopped"},
		{"not-found", "inactive", "unknown"},
		{"loaded", "maintenance", "unknown"},
		{"", "", "unknown"},
	}
	for _, c := range cases {
		if got := StatusOf(c.load, c.active); got != c.want {
			t.Errorf("StatusOf(%q, %q) = %q, want %q", c.load, c.active, got, c.want)
		}
	}
}

func TestUnitName(t *testing.T) {
	for in, want := range map[string]string{"nginx": "nginx.service", " docker ": "docker.service", "backup.timer": "backup.timer", "ssh.service": "ssh.service", "": ""} {
		if got := UnitName(in); got != want {
			t.Errorf("UnitName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnknownForAll(t *testing.T) {
	got := Unknown([]string{"a.service", "b.service"})
	if len(got) != 2 || got[0].Name != "a.service" || got[0].Status != "unknown" || got[1].Status != "unknown" {
		t.Errorf("Unknown = %+v", got)
	}
}
