package manager

import "errors"

var (
	ErrManagerNotInitialized    = errors.New("the manager must be initialized first")
	ErrManagerNotStarted        = errors.New("the manager must be started first")
	ErrManagerRunning           = errors.New("the manager is already running")
	ErrUnknownSection           = errors.New("unknown section")
	ErrUnknownSectionOrFuncName = errors.New("unknown section or eBPF function name")
	ErrPinnedObjectNotFound     = errors.New("pinned object not found")
	ErrMapNameInUse             = errors.New("the provided map name is already taken")
	ErrIdentificationPairInUse  = errors.New("the provided identification pair already exists")
	ErrProbeNotInitialized      = errors.New("the probe must be initialized first")
	ErrProbeRunning             = errors.New("the probe is already running")
	ErrSectionFormat            = errors.New("invalid section format")
	ErrSymbolNotFound           = errors.New("symbol not found")
	ErrKprobeIDNotExist         = errors.New("kprobe id file doesn't exist")
	ErrUprobeIDNotExist         = errors.New("uprobe id file doesn't exist")
	ErrKProbeHookPointNotExist  = errors.New("the kprobe hook point doesn't exist")
	ErrCloneProbeRequired       = errors.New("use CloneProbe to load 2 instances of the same program")
	ErrInterfaceNotSet          = errors.New("interface not provided: at least one of IfIndex and IfName must be set")
	ErrMapInitialized           = errors.New("map already initialized")
	ErrMapNotInitialized        = errors.New("the map must be initialized first")
	ErrMapNotRunning            = errors.New("the map is not running")
	ErrNotSupported             = errors.New("not supported")
	ErrNoNetworkDirection       = errors.New("a valid network direction is required to attach a TC classifier")
	ErrMissingEditorFlags       = errors.New("missing editor flags in map editor")
)
