package manager

import "testing"

func TestProbesSelectorBuilder(t *testing.T) {
	selectors := (NewProbesSelectorBuilder().
		AllOf(ProbeSelectorLocationRoot).
			ProbeID("uprobe__func1").
			ProbeID("uprobe__func2", ProbeIdAddRetprobe).
		BestEffort(ProbeSelectorLocationRoot).
			ProbeID("kprobe__func3").
			ProbeID("kprobe__func4", ProbeIdAddRetprobe).
			OneOf(ProbeSelectorLocationNested).
				ProbeID("kprobe__func5").
				ProbeID("kprobe__func6")).Build()

	if len(selectors) != 2 {
		t.Fatalf("expected 2 selectors, got %d", len(selectors))
	}

	allof, ok := selectors[0].(*AllOf)
	if !ok {
		t.Fatalf("expected AllOf, got %T", selectors[0])
	}

	// Testing with the String() method is easier than iterating, casting and comparing each elemet
	// and results are the same
	expectedString := "AllOf {UID: EBPFFuncName:uprobe__func1}, {UID: EBPFFuncName:uprobe__func2}, {UID: EBPFFuncName:uretprobe__func2}"
	if allof.String() != expectedString {
		t.Fatalf("expected: %s, got: %s", expectedString, allof.String())
	}

	be, ok := selectors[1].(*BestEffort)
	if !ok {
		t.Fatalf("expected BestEffort, got %T", selectors[0])
	}

	if len(be.Selectors) != 4 {
		t.Fatalf("expected 4 selectors, got %d", len(be.Selectors))
	}

	oneof, ok := be.Selectors[3].(*OneOf)
	if !ok {
		t.Fatalf("expected OneOf, got %T", be.Selectors[3])
	}

	expectedString = "OneOf {UID: EBPFFuncName:kprobe__func5}, {UID: EBPFFuncName:kprobe__func6}"
	if oneof.String() != expectedString {
		t.Fatalf("expected: %s, got: %s", expectedString, oneof.String())
	}

	expectedString = "BestEffort {UID: EBPFFuncName:kprobe__func3}, {UID: EBPFFuncName:kprobe__func4}, {UID: EBPFFuncName:kretprobe__func4}, {UID: EBPFFuncName:kprobe__func5}, {UID: EBPFFuncName:kprobe__func6}"
	if be.String() != expectedString {
		t.Fatalf("expected: %s, got: %s", expectedString, be.String())
	}
}
