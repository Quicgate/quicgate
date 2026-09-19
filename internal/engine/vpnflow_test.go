package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"quicgate/internal/wg"
)

// "No record, no flow" is about a record that was written (QG-07). With a log
// that cannot be written, an allowed flow is refused, the failure is visible,
// lost best-effort records are counted, and the first record that goes through
// again switches admission back on.
func TestAFlowLogThatCannotBeWrittenRefusesFlows(t *testing.T) {
	var mu sync.Mutex
	var broken error
	var lines int
	l := &flowLogger{queue: make(chan flowItem, 16)}
	l.write = func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if broken != nil {
			return broken
		}
		lines++
		return nil
	}
	go l.run()
	allow := wg.FlowRecord{Verdict: "allow", Dest: "192.168.1.10:22"}
	deny := wg.FlowRecord{Verdict: "deny", Dest: "192.168.1.10:23"}
	settle := func(cond func() bool) bool {
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if cond() {
				return true
			}
		}
		return false
	}

	if !l.record(allow) || lines != 1 {
		t.Fatalf("a working log: record taken = false or %d lines", lines)
	}

	mu.Lock()
	broken = errors.New("no space left on device")
	mu.Unlock()
	if l.record(allow) {
		t.Fatal("an allowed flow was admitted although its record could not be written")
	}
	if !l.failed.Load() {
		t.Fatal("the failure is not visible")
	}
	e := &Engine{flowLog: l}
	if e.FlowLogError() != "no space left on device" {
		t.Fatalf("FlowLogError = %q", e.FlowLogError())
	}
	// While it fails, admission is refused at once, without waiting on the disk.
	began := time.Now()
	for i := 0; i < 50; i++ {
		if l.record(allow) {
			t.Fatal("an allowed flow was admitted while the log fails")
		}
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("50 refusals took %v", took)
	}
	l.record(deny)
	if !settle(func() bool { return l.dropped.Load() == 1 }) {
		t.Fatalf("the lost record was not counted: dropped = %d", l.dropped.Load())
	}

	// The disk is back: the next record that is written switches admission on.
	mu.Lock()
	broken = nil
	mu.Unlock()
	l.record(deny)
	if !settle(func() bool { return !l.failed.Load() }) {
		t.Fatal("the log stays failed although it can be written again")
	}
	if !l.record(allow) || e.FlowLogError() != "" {
		t.Fatal("admission did not come back with the log")
	}
}

// A log that hangs is a log that fails: an admission waits a bounded time.
func TestAFlowLogThatHangsDoesNotHoldAdmissionsForever(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the write timeout")
	}
	release := make(chan struct{})
	l := &flowLogger{queue: make(chan flowItem, 16)}
	l.write = func([]byte) error { <-release; return nil }
	go l.run()
	defer close(release)
	began := time.Now()
	if l.record(wg.FlowRecord{Verdict: "allow"}) {
		t.Fatal("an allowed flow was admitted although its record was never written")
	}
	if took := time.Since(began); took > flowWriteWait+time.Second {
		t.Fatalf("the admission waited %v", took)
	}
	if !l.failed.Load() {
		t.Fatal("a hanging log does not count as failing")
	}
}
