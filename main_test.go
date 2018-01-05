package main

import "testing"

func TestFilterGroups(t *testing.T) {
	groupString := []string{"bob", "fred", "jim"}
	allowedGroups := []string{"bob", "andy"}

	filteredGroups := filterGroups(groupString, allowedGroups)
	if len(filteredGroups) == 0 {
		t.Error("Unexpected Result: No Groups Matched")
	} else if len(filteredGroups) != 1 {
		t.Error("Unexpected Result: More than 1 Group matched: ", filteredGroups)
	}

}

func TestReadConfig(t *testing.T) {
	allowedGroups, err := readConfig("test.csv")
	if err != nil {
		t.Errorf("Error reading config file: %s", err)
	}
	if len(allowedGroups) != 4 {
		t.Error("Unexpected result reading config file", allowedGroups)
	}
}
