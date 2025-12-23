package main

import "testing"

func TestPermissionsFromGroupSuffixes(t *testing.T) {
	tests := []struct {
		name          string
		group         string
		namespace     string
		pullOnly      bool
		deleteAllowed bool
	}{
		{name: "rwd", group: "team1_rwd", namespace: "team1", pullOnly: false, deleteAllowed: true},
		{name: "rw", group: "team2_rw", namespace: "team2", pullOnly: false, deleteAllowed: false},
		{name: "rd", group: "team3_rd", namespace: "team3", pullOnly: true, deleteAllowed: true},
		{name: "r", group: "team4_r", namespace: "team4", pullOnly: true, deleteAllowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(tt.group)
			if !ok {
				t.Fatalf("expected ok for group %q", tt.group)
			}
			if ns != tt.namespace {
				t.Fatalf("expected namespace %q, got %q", tt.namespace, ns)
			}
			if pullOnly != tt.pullOnly {
				t.Fatalf("expected pullOnly %v, got %v", tt.pullOnly, pullOnly)
			}
			if deleteAllowed != tt.deleteAllowed {
				t.Fatalf("expected deleteAllowed %v, got %v", tt.deleteAllowed, deleteAllowed)
			}
		})
	}
}
