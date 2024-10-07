package manager

import (
	"fmt"
	"regexp"
	"strings"
)

// ProbesSelector - A probe selector defines how a probe (or a group of probes) should be activated.
//
// For example, this can be used to specify that out of a group of optional probes, at least one should be activated.
type ProbesSelector interface {
	// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
	GetProbesIdentificationPairList() []ProbeIdentificationPair
	// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
	// For example, see OneOf.
	RunValidator(manager *Manager) error
	// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
	// mow select the new one
	EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair)
}

// ProbeSelector - This selector is used to unconditionally select a probe by its identification pair and validate
// that it is activated
type ProbeSelector struct {
	ProbeIdentificationPair
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (ps *ProbeSelector) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	if ps == nil {
		return nil
	}

	return []ProbeIdentificationPair{ps.ProbeIdentificationPair}
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (ps *ProbeSelector) RunValidator(manager *Manager) error {
	if ps == nil {
		return nil
	}

	p, ok := manager.GetProbe(ps.ProbeIdentificationPair)
	if !ok {
		return fmt.Errorf("probe not found: %s", ps.ProbeIdentificationPair)
	}
	if !p.IsRunning() && p.Enabled {
		return fmt.Errorf("%s: %w", ps.ProbeIdentificationPair.String(), p.GetLastError())
	}
	if !p.Enabled {
		return fmt.Errorf(
			"%s: is disabled, add it to the activation list and check that it was not explicitly excluded by the manager options",
			ps.ProbeIdentificationPair.String())
	}
	return nil
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// mow select the new one
func (ps *ProbeSelector) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	if ps.ProbeIdentificationPair == old {
		ps.ProbeIdentificationPair = new
	}
}

// OneOf - This selector is used to ensure that at least of a list of probe selectors is valid. In other words, this
// can be used to ensure that at least one of a list of optional probes is activated.
type OneOf struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (oo *OneOf) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range oo.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (oo *OneOf) RunValidator(manager *Manager) error {
	var errs []string
	for _, selector := range oo.Selectors {
		if err := selector.RunValidator(manager); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == len(oo.Selectors) {
		return fmt.Errorf(
			"OneOf requirement failed, none of the following probes are running [%s]",
			strings.Join(errs, " | "))
	}
	// at least one selector was successful
	return nil
}

func (oo *OneOf) String() string {
	var strs []string
	for _, id := range oo.GetProbesIdentificationPairList() {
		str := id.String()
		strs = append(strs, str)
	}
	return "OneOf " + strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (oo *OneOf) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range oo.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}

// AllOf - This selector is used to ensure that all the proves in the provided list are running.
type AllOf struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (ao *AllOf) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range ao.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (ao *AllOf) RunValidator(manager *Manager) error {
	var errMsg []string
	for _, selector := range ao.Selectors {
		if err := selector.RunValidator(manager); err != nil {
			errMsg = append(errMsg, err.Error())
		}
	}
	if len(errMsg) > 0 {
		return fmt.Errorf(
			"AllOf requirement failed, the following probes are not running [%s]",
			strings.Join(errMsg, " | "))
	}
	// no error means that all the selectors were successful
	return nil
}

func (ao *AllOf) String() string {
	var strs []string
	for _, id := range ao.GetProbesIdentificationPairList() {
		str := id.String()
		strs = append(strs, str)
	}
	return "AllOf " + strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (ao *AllOf) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range ao.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}

// BestEffort - This selector is used to load probes in the best effort mode
type BestEffort struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (be *BestEffort) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range be.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (be *BestEffort) RunValidator(_ *Manager) error {
	return nil
}

func (be *BestEffort) String() string {
	var strs []string
	for _, id := range be.GetProbesIdentificationPairList() {
		str := id.String()
		strs = append(strs, str)
	}
	return "BestEffort " + strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (be *BestEffort) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range be.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}

type ProbesSelectorBuilder struct {
	selectors []ProbesSelector
	currSelectorSlice *[]ProbesSelector
}

func NewProbesSelectorBuilder() *ProbesSelectorBuilder {
	b := &ProbesSelectorBuilder{
		selectors: make([]ProbesSelector, 0),
	}

	b.currSelectorSlice = &b.selectors
	return b
}

type ProbeSelectorLocation int
const (
	ProbeSelectorLocationRoot ProbeSelectorLocation = iota
	ProbeSelectorLocationNested
)

func (b *ProbesSelectorBuilder) AllOf(location ProbeSelectorLocation) *ProbesSelectorBuilder {
	allof := &AllOf{}
	if location == ProbeSelectorLocationRoot {
		b.selectors = append(b.selectors, allof)
	} else {
		*b.currSelectorSlice = append(*b.currSelectorSlice, allof)
	}
	b.currSelectorSlice = &allof.Selectors

	return b
}

func (b *ProbesSelectorBuilder) OneOf(location ProbeSelectorLocation) *ProbesSelectorBuilder {
	oneof := &OneOf{}
	if location == ProbeSelectorLocationRoot {
		b.selectors = append(b.selectors, oneof)
	} else {
		*b.currSelectorSlice = append(*b.currSelectorSlice, oneof)
	}
	b.currSelectorSlice = &oneof.Selectors

	return b
}

func (b *ProbesSelectorBuilder) BestEffort(location ProbeSelectorLocation) *ProbesSelectorBuilder {
	be := &BestEffort{}
	if location == ProbeSelectorLocationRoot {
		b.selectors = append(b.selectors, be)
	} else {
		*b.currSelectorSlice = append(*b.currSelectorSlice, be)
	}
	b.currSelectorSlice = &be.Selectors

	return b
}

type ProbeIdOptions int

const (
	ProbeIdAddRetprobe ProbeIdOptions = iota
)

var addRetRegex = regexp.MustCompile(`^(k|u)probe`)

func (b *ProbesSelectorBuilder) ProbeID(funcName string, opts ...ProbeIdOptions) *ProbesSelectorBuilder {
	pi := &ProbeIdentificationPair{
		EBPFFuncName: funcName,
	}

	*b.currSelectorSlice = append(*b.currSelectorSlice, &ProbeSelector{ProbeIdentificationPair: *pi})

	for _, opt := range opts {
		switch opt {
		case ProbeIdAddRetprobe:
			modified := addRetRegex.ReplaceAllString(funcName, "${1}retprobe")

			if modified == funcName {
				panic("ProbeIdAddRetprobe can only be used with kprobe or uprobe")
			}

			b.ProbeID(modified)
		}
	}

	return b
}

func (b *ProbesSelectorBuilder) Build() []ProbesSelector {
	return b.selectors
}
