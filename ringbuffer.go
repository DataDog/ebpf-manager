package manager

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type RingBufferOptions struct {
	// RingBufferSize - Size in bytes of the ring buffer. Defaults to the manager value if not set.
	RingBufferSize int

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

	if ringBufferOptions.TelemetryEnabled {
		ringBuffer.usageTelemetry = &atomic.Uint64{}
	}
	return &ringBuffer, nil
}

// init - Initialize a ring buffer
func (rb *RingBuffer) init(manager *Manager) error {
	rb.manager = manager

	if rb.DataHandler == nil && rb.RecordHandler == nil {
		return fmt.Errorf("no DataHandler/RecordHandler set for %s", rb.Name)
	}

	// Set default values if not already set
	if rb.RingBufferSize == 0 {
		rb.RingBufferSize = manager.options.DefaultRingBufferSize
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
		var record *ringbuf.Record
		var err error

		for {
			if rb.RingBufferOptions.RecordGetter != nil {
				record = rb.RingBufferOptions.RecordGetter()
			} else if rb.DataHandler != nil {
				record = new(ringbuf.Record)
			}

			if err = rb.ringReader.ReadInto(record); err != nil {
				if isRingBufferClosed(err) {
					rb.wgReader.Done()
					return
				}
				if rb.ErrChan != nil {
					rb.ErrChan <- err
				}
				continue
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
	if errTmp := rb.Map.close(cleanup); errTmp != nil {
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
	return rb.bufferSize
}

// Telemetry returns the usage telemetry
func (rb *RingBuffer) Telemetry() (usage uint64, ok bool) {
	if rb.usageTelemetry == nil {
		return 0, false
	}
	// reset to zero, so we return the max value between each collection
	return rb.usageTelemetry.Swap(0), true
}

func isRingBufferClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed)
}
