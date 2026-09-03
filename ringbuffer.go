package manager

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type RingBufferOptions struct {
	// ErrChan - Reader error channel
	ErrChan chan error

	// DataHandler - Callback function called when a new sample was retrieved from the perf
	// ring buffer.
	DataHandler func(CPU int, data []byte, ringBuffer *RingBuffer, manager *Manager)

	// RecordHandler - Callback function called when a new record was retrieved from the perf
	// ring buffer.
	RecordHandler func(record *ringbuf.Record, ringBuffer *RingBuffer, manager *Manager)

	// RecordGetter - if specified this getter will be used to get a new record
	RecordGetter func() *ringbuf.Record

	// TelemetryEnabled turns on telemetry about the usage of the ring buffer
	TelemetryEnabled bool

	// SchedPolicy - If set, the reader goroutine's OS thread will be pinned
	// (LockOSThread) and given this scheduling policy via sched_setattr(2).
	// Supported values: unix.SCHED_FIFO, unix.SCHED_RR. Zero means no change.
	SchedPolicy int

	// SchedPriority - RT scheduling priority (1-99). Required when SchedPolicy is set.
	SchedPriority int
}

type RingBuffer struct {
	manager        *Manager
	ringReader     *ringbuf.Reader
	wgReader       sync.WaitGroup
	bufferSize     int
	usageTelemetry *atomic.Uint64

	// Map - A PerfMap has the same features as a normal Map
	Map
	RingBufferOptions
}

// loadNewRingBuffer - Creates a new ring buffer map instance, loads it and sets up the ring buffer reader
func loadNewRingBuffer(spec *ebpf.MapSpec, options MapOptions, ringBufferOptions RingBufferOptions) (*RingBuffer, error) {
	ringBuffer := RingBuffer{
		Map: Map{
			arraySpec:  spec,
			Name:       spec.Name,
			MapOptions: options,
		},
		RingBufferOptions: ringBufferOptions,
	}

	var err error
	if ringBuffer.array, err = ebpf.NewMap(spec); err != nil {
		return nil, err
	}

	if ringBuffer.PinPath != "" {
		if err = ringBuffer.array.Pin(ringBuffer.PinPath); err != nil {
			return nil, fmt.Errorf("couldn't pin map %s at %s: %w", ringBuffer.Name, ringBuffer.PinPath, err)
		}
	}

	return &ringBuffer, nil
}

// init - Initialize a ring buffer
func (rb *RingBuffer) init(manager *Manager) error {
	rb.manager = manager

	if rb.DataHandler == nil && rb.RecordHandler == nil {
		return fmt.Errorf("no DataHandler/RecordHandler set for %s", rb.Name)
	}

	if rb.SchedPolicy != 0 {
		if rb.SchedPolicy != unix.SCHED_FIFO && rb.SchedPolicy != unix.SCHED_RR {
			return fmt.Errorf("unsupported SchedPolicy %d for %s: must be SCHED_FIFO or SCHED_RR", rb.SchedPolicy, rb.Name)
		}
		if rb.SchedPriority < 1 || rb.SchedPriority > 99 {
			return fmt.Errorf("SchedPriority must be between 1 and 99 for %s, got %d", rb.Name, rb.SchedPriority)
		}
	}

	if rb.TelemetryEnabled {
		rb.usageTelemetry = &atomic.Uint64{}
	}

	// Initialize the underlying map structure
	if err := rb.Map.init(); err != nil {
		return err
	}
	return nil
}

// Start - Starts fetching events on a perf ring buffer
func (rb *RingBuffer) Start() error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state == running {
		return nil
	}
	if rb.state < initialized {
		return ErrMapNotInitialized
	}

	// Create and start the perf map
	var err error
	if rb.ringReader, err = ringbuf.NewReader(rb.array); err != nil {
		return err
	}
	rb.bufferSize = rb.ringReader.BufferSize()
	// Start listening for data
	rb.wgReader.Add(1)

	go func() {
		if rb.SchedPolicy != 0 {
			runtime.LockOSThread()
			// No UnlockOSThread — the goroutine runs for the ring buffer's
			// lifetime and the thread is destroyed when it exits.
			attr, err := unix.SchedGetAttr(0, 0)
			if err == nil {
				attr.Policy = uint32(rb.SchedPolicy)
				attr.Priority = uint32(rb.SchedPriority)
				err = unix.SchedSetAttr(0, attr, 0)
			}
			if err != nil {
				if rb.ErrChan != nil {
					rb.ErrChan <- fmt.Errorf("failed to set RT scheduling policy on ring buffer reader: %w", err)
				}
				// Continue with normal scheduling (graceful degradation)
			}
		}

		var record *ringbuf.Record
		var err error

		for {
			if rb.RecordGetter != nil {
				record = rb.RecordGetter()
			} else if rb.DataHandler != nil {
				record = new(ringbuf.Record)
			}

			if err = rb.ringReader.ReadInto(record); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					rb.wgReader.Done()
					return
				}
				if errors.Is(err, ringbuf.ErrFlushed) {
					record.RawSample = record.RawSample[:0]
				} else {
					if rb.ErrChan != nil {
						rb.ErrChan <- err
					}
					continue
				}
			}

			if rb.usageTelemetry != nil {
				updateMaxTelemetry(rb.usageTelemetry, uint64(record.Remaining))
			}
			if rb.RecordHandler != nil {
				rb.RecordHandler(record, rb, rb.manager)
			} else if rb.DataHandler != nil {
				rb.DataHandler(0, record.RawSample, rb, rb.manager)
			}
		}
	}()

	rb.state = running
	return nil
}

// Flush unblocks the underlying reader and will cause the pending samples to be read
func (rb *RingBuffer) Flush() {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state != running {
		return
	}

	_ = rb.ringReader.Flush()
}

// Stop - Stops the perf ring buffer
func (rb *RingBuffer) Stop(cleanup MapCleanupType) error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state <= stopped {
		return nil
	}
	rb.state = stopped

	// close ring reader
	err := rb.ringReader.Close()

	rb.wgReader.Wait()

	// close underlying map
	if errTmp := rb.close(cleanup); errTmp != nil {
		if err == nil {
			err = errTmp
		} else {
			err = fmt.Errorf("%s: %w", err.Error(), errTmp)
		}
	}

	return err
}

// BufferSize returns the size in bytes of the ring buffer
func (rb *RingBuffer) BufferSize() int {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	return rb.bufferSize
}

// Telemetry returns the usage telemetry
func (rb *RingBuffer) Telemetry() (usage uint64, ok bool) {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state < initialized || rb.usageTelemetry == nil {
		return 0, false
	}
	// reset to zero, so we return the max value between each collection
	return rb.usageTelemetry.Swap(0), true
}
