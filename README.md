## eBPF Manager
[![](https://godoc.org/github.com/DataDog/ebpf-manager?status.svg)](https://godoc.org/github.com/DataDog/ebpf-manager)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/mit)

This repository implements a manager on top of [Cilium's eBPF library](https://github.com/cilium/ebpf). This declarative manager simplifies attaching and detaching eBPF programs by controlling their entire life cycle. It was built with the intention of unifying how eBPF is used in large scale projects such as the [Datadog Agent](https://github.com/DataDog/datadog-agent). By using the same declarative conventions, multiple teams can quickly collaborate on complex eBPF programs by sharing maps, programs or even hook points without having to worry about the setup of complex program types.

### Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)
* Linux 4.4+ (some eBPF features are only available on newer kernel versions, see [eBPF features by Linux version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md))

### Getting started

You can find many examples using the manager in [examples/](https://github.com/DataDog/ebpf-manager/tree/main/examples). For a real world use case, check out the [Datadog Agent](https://github.com/DataDog/datadog-agent).

### Useful resources

* [Cilium eBPF library](https://github.com/cilium/ebpf)
* [Cilium eBPF documentation](https://cilium.readthedocs.io/en/latest/bpf/#bpf-guide)
* [Linux documentation on BPF](http://elixir.free-electrons.com/linux/latest/source/Documentation/networking/filter.txt)
* [eBPF features by Linux version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)

## License

- Unless explicitly specified otherwise, the golang code in this repository is under the MIT License.
- The eBPF programs are under the GPL v2 License.
### Grouped uprobes

Set `Options.UprobeMultiPrograms` to the eBPF function names whose application
uprobes should use multi-uprobe links. The manager selects and loads their
compatible programs before attachment. It copies reachable tail-call programs
and program arrays from `TailCallRouter`, retaining the original routes for
legacy callers such as kernel probes. Data maps remain shared. Declare the
complete, static tail-call routes at initialization; later updates of the
original routes do not update their multi-uprobe copies.

After initialization, check `Manager.UprobeMultiStatus()`. Unsupported kernels
or failed optional preparation/loading select the legacy backend and return the
fallback reason through that method. Existing callers remain on the legacy
backend unless they opt in. Multi-uprobes require Linux 6.6 or a suitable
backport; support is detected at runtime.

When multi is selected, `AddHook` accepts `Probe.UprobeOffsets` containing the
resolved file offsets for one program and binary. One `ProbeIdentificationPair`
owns the group, so `DetachHook`, `Stop`, selectors and pause/resume use the normal
manager lifecycle. Use individual hooks if legacy was selected. Native return
probes retain their `uretprobe/` section; manually discovered Go return
instructions remain `uprobe/` locations. PID scope uses `PerfEventPID` as usual.

The isolated real-kernel test is opt-in:

```
EBPF_MANAGER_UPROBE_MULTI_TEST=1 go test -run 'TestMultiUprobeIntegration|TestMultiUprobeLoadFallback' -v
```

Run it in a privileged disposable Linux environment. It attaches only to its
own test executable, checks multi-offset capture and legacy decoder coexistence,
and exercises shared data maps, pause/resume and detachment.
