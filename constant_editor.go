package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ConstantEditor - A constant editor tries to rewrite the value of a constant in a compiled eBPF program.
//
// Constant edition only works before the eBPF programs are loaded in the kernel, and therefore before the
// Manager is started. If no program sections are provided, the manager will try to edit the constant in all eBPF programs.
type ConstantEditor struct {
	// Name - Name of the constant to rewrite
	Name string

	// Value - Value to write in the eBPF bytecode. When using the asm load method, the Value has to be a `uint64`.
	Value interface{}

	// FailOnMissing - If FailOMissing is set to true, the constant edition process will return an error if the constant
	// was missing in at least one program
	FailOnMissing bool

	// BTFGlobalConstant - Indicates if the constant is a BTF global constant.
	BTFGlobalConstant bool

	// ProbeIdentificationPairs - Identifies the list of programs to edit. If empty, it will apply to all the programs
	// of the manager. Will return an error if at least one edition failed.
	ProbeIdentificationPairs []ProbeIdentificationPair
}

// editConstants - newEditor the programs in the CollectionSpec with the provided constant editors. Tries with the BTF global
// variable first, and fall back to the asm method if BTF is not available.
func (m *Manager) editConstants() error {
	// Start with the BTF based solution
	rodata := m.collectionSpec.Maps[".rodata"]
	if rodata != nil && rodata.Key != nil {
		for _, editor := range m.options.ConstantEditors {
			if !editor.BTFGlobalConstant {
				continue
			}
			constant := map[string]interface{}{
				editor.Name: editor.Value,
			}
			if err := m.collectionSpec.RewriteConstants(constant); err != nil && editor.FailOnMissing {
				return err
			}
		}
	}

	// Fall back to the old school constant edition
	for _, constantEditor := range m.options.ConstantEditors {
		if constantEditor.BTFGlobalConstant {
			continue
		}

		// newEditor the constant of the provided programs
		for _, id := range constantEditor.ProbeIdentificationPairs {
			programs, found, err := m.GetProgramSpec(id)
			if err != nil {
				return err
			}
			if !found || len(programs) == 0 {
				return fmt.Errorf("couldn't find programSpec %v: %w", id, ErrUnknownSectionOrFuncName)
			}
			prog := programs[0]

			// newEditor program
			if err := m.editConstant(prog, constantEditor); err != nil {
				return fmt.Errorf("couldn't edit %s in %v: %w", constantEditor.Name, id, err)
			}
		}
	}

	// Apply to all programs if no section was provided
	for section, prog := range m.collectionSpec.Programs {
		var edit *editor
		for _, constantEditor := range m.options.ConstantEditors {
			if constantEditor.BTFGlobalConstant {
				continue
			}

			if len(constantEditor.ProbeIdentificationPairs) != 0 {
				continue
			}

			if edit == nil {
				edit = newEditor(&prog.Instructions)
			}

			if err := m.editConstantWithEditor(edit, constantEditor); err != nil {
				return fmt.Errorf("couldn't edit %s in %s: %w", constantEditor.Name, section, err)
			}
		}
	}

	return nil
}

// editConstant - newEditor the provided program with the provided constant using the asm method.
func (m *Manager) editConstant(prog *ebpf.ProgramSpec, editor ConstantEditor) error {
	edit := newEditor(&prog.Instructions)
	return m.editConstantWithEditor(edit, editor)
}

func (m *Manager) editConstantWithEditor(edit *editor, editor ConstantEditor) error {
	data, ok := (editor.Value).(uint64)
	if !ok {
		return fmt.Errorf("with the asm method, the constant value has to be of type uint64")
	}
	if err := edit.RewriteConstant(editor.Name, data); err != nil {
		if isUnreferencedSymbol(err) && editor.FailOnMissing {
			return err
		}
	}
	return nil
}
