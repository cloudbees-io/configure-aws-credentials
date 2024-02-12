package core

import "testing"

func TestDirExists(t *testing.T) {
	tests := []struct {
		path       string
		required   bool
		shouldFail bool
	}{
		{"../core", true, false},           // existing directory
		{"../core", false, false},          // existing directory, not required
		{"./nonexistentdir", true, true},   // non-existing directory, required
		{"./nonexistentdir", false, false}, // non-existing directory, not required
		{"", true, true},                   // empty path, required
		{"", false, true},                  // empty path, not required
	}

	for _, test := range tests {
		err := DirExists(test.path, test.required)
		if test.shouldFail && err == nil {
			t.Errorf("Expected error for path '%s' required=%t but got nil", test.path, test.required)
		} else if !test.shouldFail && err != nil {
			t.Errorf("Unexpected error for path '%s' required=%t: %v", test.path, test.required, err)
		}
	}
}
