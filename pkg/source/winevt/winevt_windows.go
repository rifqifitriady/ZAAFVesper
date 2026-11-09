//go:build windows

package winevt

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
	"github.com/rifqifitriady/ZAAFVesper/pkg/winproc"
)

var (
	wevtapi          = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
)

// winevt.h
const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	batchSize                  = 64
	errorEvtChannelNotFound    = windows.Errno(15007)
	errorEvtQueryResultStale   = windows.Errno(15011)
	// maxRenderBytes bounds one rendered event (UTF-16).
	maxRenderBytes = 2 * sysmon.MaxEventBytes
)

// Source reads Sysmon from the Windows event log.
type Source struct {
	cfg  Config
	feed atomic.Pointer[sysmon.Feeder]
	buf  []uint16
	// oversize counts events larger than maxRenderBytes (dropped).
	oversize atomic.Uint64
	pending  func(string, string)
}

// New returns the source.
func New(cfg Config) *Source { return &Source{cfg: cfg} }

// Name implements source.Source.
func (s *Source) Name() string { return Name }

// OnDegraded registers fn for sysmon.CondEventsDropped (record id gaps).
// Call it before Run.
func (s *Source) OnDegraded(fn func(condition, detail string)) { s.pending = fn }

// Stats implements source.Source.
func (s *Source) Stats() map[string]uint64 {
	f := s.feed.Load()
	if f == nil {
		f = sysmon.NewFeeder(nil, nil) // zero counters before Run
	}
	st := f.Stats()
	st["oversize"] = s.oversize.Load()
	return st
}

// ReadStamp is the kernel identity reader for the Binder: the creation time
// of pid (GetProcessTimes).
func ReadStamp(pid int32) (sysmon.Stamp, error) {
	h, err := winproc.OpenQuery(uint32(pid))
	if err != nil {
		return sysmon.Stamp{}, err
	}
	defer windows.CloseHandle(h)
	ft, t, err := winproc.CreationTime(h)
	if err != nil {
		return sysmon.Stamp{}, err
	}
	return sysmon.Stamp{ID: ft, Start: t, Precise: t}, nil
}

func call(p *windows.LazyProc, args ...uintptr) (uintptr, error) {
	r, _, err := p.Call(args...)
	if r == 0 {
		if errno, ok := err.(windows.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, fmt.Errorf("%s failed", p.Name)
	}
	return r, nil
}

func evtClose(h uintptr) { _, _, _ = procEvtClose.Call(h) }

// Run subscribes to future events of the Sysmon channel and feeds them to
// out until ctx ends.
func (s *Source) Run(ctx context.Context, events []string, out chan<- *event.Event) error {
	if err := wevtapi.Load(); err != nil {
		return fmt.Errorf("winevt: %w", err)
	}
	feed := sysmon.NewFeeder(events, sysmon.NewBinder(ReadStamp, IdentityTolerance))
	prov := &provenance{}
	feed.Trust = prov.check
	if s.pending != nil {
		feed.OnDegraded(s.pending)
	}
	s.feed.Store(feed)
	signal, err := windows.CreateEvent(nil, 1, 1, nil) // manual reset, initially set
	if err != nil {
		return err
	}
	defer windows.CloseHandle(signal)
	cancel, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(cancel)
	ch, _ := windows.UTF16PtrFromString(Channel)
	q, _ := windows.UTF16PtrFromString(Query)
	sub, err := call(procEvtSubscribe, 0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), 0, 0, 0, evtSubscribeToFutureEvents)
	switch {
	case errors.Is(err, errorEvtChannelNotFound):
		return fmt.Errorf("winevt: channel %s not found: install Sysmon (see packaging/windows/README.md)", Channel)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("winevt: access to %s denied: run as an administrator or as the ZAAFVesper service (LocalSystem)", Channel)
	case err != nil:
		return fmt.Errorf("winevt: EvtSubscribe(%s): %w", Channel, err)
	}
	defer evtClose(sub)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = windows.SetEvent(cancel)
		case <-done:
		}
	}()
	s.logf("subscribed to %s (future events)", Channel)
	handles := make([]uintptr, batchSize)
	for {
		w, err := windows.WaitForMultipleObjects([]windows.Handle{signal, cancel}, false, windows.INFINITE)
		if err != nil {
			return fmt.Errorf("winevt: wait: %w", err)
		}
		if w == windows.WAIT_OBJECT_0+1 {
			return nil
		}
		// Reset before draining: an event that arrives during the drain sets
		// the signal again, so nothing waits for a later event to be read.
		_ = windows.ResetEvent(signal)
		for {
			var got uint32
			_, err := call(procEvtNext, sub, batchSize, uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&got)))
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) || errors.Is(err, windows.ERROR_TIMEOUT) {
				break
			}
			if errors.Is(err, errorEvtQueryResultStale) {
				// The log wrapped past unread events.
				feed.Restarted(false)
				s.logf("event log overwrote unread Sysmon events (query result stale)")
				break
			}
			if err != nil {
				return fmt.Errorf("winevt: EvtNext: %w", err)
			}
			for i := uint32(0); i < got && i < batchSize; i++ {
				raw, rerr := s.render(handles[i])
				evtClose(handles[i])
				if rerr != nil {
					feed.Unreadable("EvtRender: " + rerr.Error())
					continue
				}
				if err := feed.Handle(ctx, raw, out); err != nil {
					for j := i + 1; j < got && j < batchSize; j++ {
						evtClose(handles[j])
					}
					return nil
				}
			}
		}
	}
}

// render returns the event's XML as UTF-8, at most maxRenderBytes of UTF-16.
func (s *Source) render(h uintptr) ([]byte, error) {
	if s.buf == nil {
		s.buf = make([]uint16, 16<<10)
	}
	for attempt := 0; attempt < 2; attempt++ {
		var used, props uint32
		_, err := call(procEvtRender, 0, h, evtRenderEventXML, uintptr(len(s.buf)*2), uintptr(unsafe.Pointer(&s.buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			if used > maxRenderBytes {
				s.oversize.Add(1)
				return nil, sysmon.ErrTooLarge
			}
			s.buf = make([]uint16, used/2+1)
			continue
		}
		if err != nil {
			return nil, err
		}
		n := int(used / 2)
		if n > len(s.buf) {
			n = len(s.buf)
		}
		return []byte(windows.UTF16ToString(s.buf[:n])), nil
	}
	return nil, errors.New("winevt: EvtRender buffer")
}

func (s *Source) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// provenance holds the Sysmon service pids for checkProvenance
// (provenance.go), refreshed from the Service Control Manager at most every
// provenanceRefresh when an unknown writer pid is seen.
type provenance struct {
	pids      map[uint32]bool
	refreshed time.Time
}

const provenanceRefresh = 5 * time.Second

func (p *provenance) check(r *sysmon.Record) error {
	return checkProvenance(r, func(pid uint32) bool {
		if p.pids[pid] {
			return true
		}
		if time.Since(p.refreshed) >= provenanceRefresh {
			p.pids, p.refreshed = sysmonServicePIDs(), time.Now()
		}
		return p.pids[pid]
	})
}

// sysmonServicePIDs asks the Service Control Manager for the process ids of
// the running Sysmon services.
func sysmonServicePIDs() map[uint32]bool {
	out := map[uint32]bool{}
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return out
	}
	defer windows.CloseServiceHandle(m)
	for _, name := range sysmonServices {
		n, _ := windows.UTF16PtrFromString(name)
		h, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		var st windows.SERVICE_STATUS_PROCESS
		var need uint32
		if windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need) == nil &&
			st.CurrentState == windows.SERVICE_RUNNING && st.ProcessId != 0 {
			out[st.ProcessId] = true
		}
		_ = windows.CloseServiceHandle(h)
	}
	return out
}
