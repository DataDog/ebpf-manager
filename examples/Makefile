PROGRAMS := $(wildcard programs/*)
EXAMPLES := \
	activated_probes \
	clone_vs_add_hook \
	constant_editor \
	instruction_patching \
	map_rewrite_vs_map_router \
	mapspec_editor \
	object_pinning \
	program_router \
	$(PROGRAMS) \
	tests_and_benchmarks

.PHONY: all $(EXAMPLES)
all: $(EXAMPLES)

$(EXAMPLES):
	$(MAKE) --directory=$@ $(TARGET)
