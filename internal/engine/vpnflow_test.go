package engine

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"quicgate/internal/wg"
)

// settle polls cond for up to two seconds.
func settle(cond func() bool) bool {
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// "No record, no flow" is about a record that was written (QG-07). With a log
// that cannot be written, an allowed flow is refused, the failure is visible,
// lost best-effort records are counted, and admission comes back when the
// record of an allowed flow goes through again: a best-effort record that
// happens to be written says nothing about whether the log keeps up.
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
	e := &Engine{flowLog: l, wg: wg.New()}
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
	if e.FlowLogDropped() != 1 {
		t.Fatalf("FlowLogDropped = %d, want 1", e.FlowLogDropped())
	}

	// The disk is back. A best-effort record going through does not switch
	// admission on: only an admission's own record proves the log keeps up.
	mu.Lock()
	broken = nil
	mu.Unlock()
	l.record(deny)
	if settle(func() bool { return !l.failed.Load() }) {
		t.Fatal("a best-effort record switched admission back on")
	}
	// The next allowed flow probes the log, and its record goes through.
	if !l.record(allow) || l.failed.Load() || e.FlowLogError() != "" {
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

// gatedLog is a flow log whose writes wait for the test's leave, one token
// each, and report when they start.
type gatedLog struct {
	mu      sync.Mutex
	lines   []wg.FlowRecord
	entered chan struct{} // one message per write that started
	allow   chan struct{} // one token per write that may finish
}

func newGatedLog(t *testing.T, queue int) (*flowLogger, *gatedLog) {
	t.Helper()
	g := &gatedLog{entered: make(chan struct{}, 64), allow: make(chan struct{})}
	l := &flowLogger{queue: make(chan flowItem, queue), wait: 200 * time.Millisecond}
	l.write = func(b []byte) error {
		g.entered <- struct{}{}
		<-g.allow
		var rec wg.FlowRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
		g.mu.Lock()
		g.lines = append(g.lines, rec)
		g.mu.Unlock()
		return nil
	}
	go l.run()
	return l, g
}

func (g *gatedLog) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.lines)
}

func (g *gatedLog) line(i int) wg.FlowRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lines[i]
}

// An admission that gives up waiting for its record refuses the flow, so the
// log must not say "allow" for it (L-35): a record still queued is written as
// a refusal, and one that was on its way when the admission gave up is
// followed by a refusal. Neither brings admission back; the first record
// written in time does.
func TestARefusedFlowIsNeverLeftInTheLogAsAllowed(t *testing.T) {
	l, g := newGatedLog(t, 16)
	res := make(chan bool, 1)
	admit := func(dst string) { go func() { res <- l.record(wg.FlowRecord{Verdict: "allow", Dest: dst}) }() }

	// The writer is busy with a best-effort record when the admission's
	// record joins the queue; the admission gives up before it is written.
	l.record(wg.FlowRecord{Verdict: "deny", Dest: "d0"})
	<-g.entered
	admit("a1")
	if <-res {
		t.Fatal("a flow was admitted although its record was not written in time")
	}
	if !l.failed.Load() {
		t.Fatal("a log that is too slow does not count as failing")
	}
	g.allow <- struct{}{} // d0 is written
	<-g.entered           // a1 is being written
	g.allow <- struct{}{}
	if !settle(func() bool { return g.count() == 2 }) {
		t.Fatalf("%d lines written, want 2", g.count())
	}
	if rec := g.line(1); rec.Dest != "a1" || rec.Verdict != "deny" || rec.Reason == "" {
		t.Fatalf("the record of the refused flow was written as %+v, want a deny with a reason", rec)
	}
	if !l.failed.Load() {
		t.Fatal("a best-effort record that was written switched admission back on")
	}

	// The writer has the admission's record and is writing it when the
	// admission gives up: the allow line is out, so a refusal follows it.
	admit("a2")
	<-g.entered // the writer has claimed a2
	if <-res {
		t.Fatal("a flow was admitted although its record was not written in time")
	}
	g.allow <- struct{}{} // the allow line
	<-g.entered           // the refusal that follows
	g.allow <- struct{}{}
	if !settle(func() bool { return g.count() == 4 }) {
		t.Fatalf("%d lines written, want 4", g.count())
	}
	if first, second := g.line(2), g.line(3); first.Dest != "a2" || first.Verdict != "allow" || second.Dest != "a2" || second.Verdict != "deny" {
		t.Fatalf("a late record left the log saying %s then %s for a2, want allow then deny", first.Verdict, second.Verdict)
	}
	if !l.failed.Load() {
		t.Fatal("a record that arrived too late switched admission back on")
	}

	// The log keeps up again: the next admission's record is written in
	// time, and that is what switches admission back on.
	close(g.allow)
	if !l.record(wg.FlowRecord{Verdict: "allow", Dest: "a3"}) || l.failed.Load() {
		t.Fatal("admission did not come back with a record written in time")
	}
	if rec := g.line(4); rec.Dest != "a3" || rec.Verdict != "allow" {
		t.Fatalf("the admitted flow's record = %+v", rec)
	}
}

// An allowed flow refused because the queue is full is a lost record: it is
// counted, so the Overview shows that LAN access is being refused (M-16).
func TestAFullFlowLogQueueCountsTheFlowsItRefuses(t *testing.T) {
	l, g := newGatedLog(t, 1)
	defer close(g.allow)
	l.record(wg.FlowRecord{Verdict: "deny", Dest: "d0"})
	<-g.entered // the writer holds d0; the queue is empty
	l.record(wg.FlowRecord{Verdict: "deny", Dest: "d1"})
	// The queue is full.
	began := time.Now()
	if l.record(wg.FlowRecord{Verdict: "allow", Dest: "a1"}) {
		t.Fatal("a flow was admitted although its record could not be queued")
	}
	if took := time.Since(began); took > 100*time.Millisecond {
		t.Fatalf("a refusal for a full queue took %v: it must not wait", took)
	}
	if l.dropped.Load() != 1 {
		t.Fatalf("dropped = %d after an allowed flow was refused for a full queue, want 1", l.dropped.Load())
	}
	if l.failed.Load() {
		t.Fatal("a full queue was taken for a broken log")
	}
	l.record(wg.FlowRecord{Verdict: "deny", Dest: "d2"})
	if l.dropped.Load() != 2 {
		t.Fatalf("dropped = %d after a best-effort record was refused too, want 2", l.dropped.Load())
	}
}

// The guard's answers about this machine are kept for a while: admission asks
// on every new flow, and the interfaces, the routing table and the listeners
// are not read for each (M-15).
func TestGuardAnswersAreCached(t *testing.T) {
	calls := 0
	ports := memo(50*time.Millisecond, func() []uint16 { calls++; return []uint16{uint16(calls)} })
	for i := 0; i < 100; i++ {
		if got := ports(); len(got) != 1 || got[0] != 1 {
			t.Fatalf("call %d returned %v", i, got)
		}
	}
	if calls != 1 {
		t.Fatalf("the answer was computed %d times in 100 calls", calls)
	}
	time.Sleep(70 * time.Millisecond)
	if got := ports(); len(got) != 1 || got[0] != 2 || calls != 2 {
		t.Fatalf("after the TTL the answer was %v after %d computations, want a fresh one", got, calls)
	}
}
