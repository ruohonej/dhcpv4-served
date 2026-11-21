package events

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	redirectQueueSize = 16
	flushTimeout      = 100 * time.Millisecond
)

// Journal descriptors are inherited streams. The worker never connects to a
// journal or remote collector.
type journalFD int

func (fd journalFD) Write(p []byte) (int, error) {
	return unix.SendmsgN(int(fd), p, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
}

type redirectedFD struct{ file *os.File }

func (fd redirectedFD) Write(p []byte) (int, error) {
	// os.File.Write raises SIGPIPE for a broken standard stream. Keep EPIPE
	// as a delivery error so a closed reader cannot stop the worker.
	raw, err := fd.file.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var writeErr error
	if err := raw.Control(func(fd uintptr) {
		n, writeErr = unix.Write(int(fd), p)
	}); err != nil {
		return 0, err
	}
	return n, writeErr
}

func workerOutput(file *os.File) (io.Writer, bool) {
	fd := int(file.Fd())
	if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err == nil {
		return journalFD(fd), false
	}
	return redirectedFD{file: file}, true
}

type record struct {
	data []byte
	at   time.Time
}

type writerQueue struct {
	records chan record
	done    chan struct{}
	abandon chan struct{}
}

func startWriter(write func(record) error) *writerQueue {
	q := &writerQueue{
		records: make(chan record, redirectQueueSize),
		done:    make(chan struct{}),
		abandon: make(chan struct{}),
	}
	go func() {
		defer close(q.done)
		for item := range q.records {
			select {
			case <-q.abandon:
				return
			default:
				_ = write(item)
			}
		}
	}()
	return q
}

func (q *writerQueue) enqueue(item record) bool {
	// slog reuses its encoding buffer after Write returns.
	item.data = bytes.Clone(item.data)
	select {
	case q.records <- item:
		return true
	default:
		return false
	}
}

type delivery struct {
	primary, fallback             io.Writer
	primaryQueue, fallbackQueue   *writerQueue
	now                           func() time.Time
	queueDrops, writeFailures     atomic.Uint64
	reportedDrops, reportedWrites uint64 // owned by the primary writer

	fallbackMu     sync.Mutex
	nextFallback   time.Time
	fallbackClosed bool
}

func (d *delivery) Write(p []byte) (int, error) {
	item := record{data: p, at: d.now()}
	if d.primaryQueue == nil {
		if err := d.writePrimary(item); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if d.primaryQueue.enqueue(item) {
		return len(p), nil
	}
	d.queueDrops.Add(1)
	d.tryFallback(item)
	return 0, unix.EAGAIN
}

func (d *delivery) writePrimary(item record) error {
	payload := item.data
	heartbeat := bytes.Contains(payload, []byte(`"event_id":"worker.heartbeat"`))
	var drops, failures uint64
	if heartbeat {
		drops, failures = d.queueDrops.Load(), d.writeFailures.Load()
		newDrops, newFailures := drops-d.reportedDrops, failures-d.reportedWrites
		payload = bytes.Clone(bytes.TrimSuffix(item.data, []byte("}\n")))
		payload = strconv.AppendUint(append(payload, `,"delivery_queue_drops":`...), newDrops, 10)
		payload = strconv.AppendUint(append(payload, `,"delivery_write_failures":`...), newFailures, 10)
		payload = strconv.AppendUint(append(payload, `,"delivery_failures":`...), newDrops+newFailures, 10)
		payload = append(payload, '}', '\n')
	}
	if err := writeRecord(d.primary, payload); err != nil {
		d.writeFailures.Add(1)
		d.tryFallback(item)
		return err
	}
	if heartbeat {
		d.reportedDrops, d.reportedWrites = drops, failures
	}
	return nil
}

func (d *delivery) tryFallback(item record) {
	d.fallbackMu.Lock()
	defer d.fallbackMu.Unlock()
	terminal := bytes.Contains(item.data, []byte(`"severity":"ERROR"`))
	if d.fallbackClosed || (!terminal && item.at.Before(d.nextFallback)) {
		return
	}
	if deadline := item.at.Add(time.Minute); deadline.After(d.nextFallback) {
		d.nextFallback = deadline
	}
	// Both descriptors can lead to the same journal. Preserve the original
	// event and mark delivery as unknown.
	item.data = append(bytes.Clone(bytes.TrimSuffix(item.data, []byte("}\n"))), `,"audit_delivery":"unknown"}`...)
	item.data = append(item.data, '\n')
	if d.fallbackQueue == nil {
		_ = d.writeFallback(item)
	} else if !d.fallbackQueue.enqueue(item) {
		d.queueDrops.Add(1)
	}
}

func (d *delivery) writeFallback(item record) error {
	err := writeRecord(d.fallback, item.data)
	if err != nil {
		d.writeFailures.Add(1)
	}
	return err
}

func writeRecord(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return err
}

func (d *delivery) close() {
	if d.primaryQueue == nil && d.fallbackQueue == nil {
		return
	}
	timer := time.NewTimer(flushTimeout)
	defer timer.Stop()
	if d.primaryQueue != nil {
		close(d.primaryQueue.records)
		select {
		case <-d.primaryQueue.done:
		case <-timer.C:
			close(d.primaryQueue.abandon)
			d.closeFallback()
			if d.fallbackQueue != nil {
				close(d.fallbackQueue.abandon)
			}
			return
		}
	}
	if d.fallbackQueue != nil {
		d.closeFallback()
		select {
		case <-d.fallbackQueue.done:
		case <-timer.C:
			close(d.fallbackQueue.abandon)
		}
	}
}

func (d *delivery) closeFallback() {
	d.fallbackMu.Lock()
	defer d.fallbackMu.Unlock()
	d.fallbackClosed = true
	if d.fallbackQueue != nil {
		close(d.fallbackQueue.records)
	}
}
