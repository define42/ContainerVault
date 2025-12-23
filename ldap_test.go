package main

import "testing"

func TestPermissionsFromGroupSuffixes(t *testing.T) {
	tests := []struct {
		name          string
		group         string
		namespace     string
		pullOnly      bool
		deleteAllowed bool
		ok            bool
	}{
		{name: "rwd", group: "team1_rwd", namespace: "team1", pullOnly: false, deleteAllowed: true, ok: true},
		{name: "rw", group: "team2_rw", namespace: "team2", pullOnly: false, deleteAllowed: false, ok: true},
		{name: "rd", group: "team3_rd", namespace: "team3", pullOnly: true, deleteAllowed: true, ok: true},
		{name: "r", group: "team4_r", namespace: "team4", pullOnly: true, deleteAllowed: false, ok: true},
		{name: "bare", group: "team5", namespace: "", pullOnly: false, deleteAllowed: false, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(tt.group)
			if ok != tt.ok {
				t.Fatalf("expected ok %v for group %q, got %v", tt.ok, tt.group, ok)
			}
			if ok {
				if ns != tt.namespace {
					t.Fatalf("expected namespace %q, got %q", tt.namespace, ns)
				}
				if pullOnly != tt.pullOnly {
					t.Fatalf("expected pullOnly %v, got %v", tt.pullOnly, pullOnly)
				}
				if deleteAllowed != tt.deleteAllowed {
					t.Fatalf("expected deleteAllowed %v, got %v", tt.deleteAllowed, deleteAllowed)
				}
			}
		})
	}
}
