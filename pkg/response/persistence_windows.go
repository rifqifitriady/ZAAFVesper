//go:build windows

package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// maxTaskBytes caps a task definition read by remove_persistence.
const maxTaskBytes = 1 << 20

// tasksDir is where the Task Scheduler keeps task definitions.
var tasksDir = filepath.Join(systemDir, "Tasks")

// servicesExe is the Service Control Manager: it writes a service's
// registry key for whoever called CreateService.
var servicesExe = filepath.Join(systemDir, "services.exe")

// svchostExe hosts the Task Scheduler, which writes a task file for
// whoever registered the task. Both are compared ASCII-only
// (equalASCIIFold), as every trust decision.
var svchostExe = filepath.Join(systemDir, "svchost.exe")

// persist handles, after its event:
//
//   - a value of a Run or RunOnce key (HKLM or HKU\<SID>, 64- and 32-bit
//     views), set by an untrusted process: deleted when its data is still
//     what the event reported; the value is saved in the vault.
//   - a service whose ImagePath was set: when the Service Control Manager
//     still has that exact command line, the service runs a program from
//     outside the system folders, is a Win32 service and not a protected
//     one (Defender, Sysmon, EventLog, ZAAFVesper and other core
//     services), it is stopped and deleted; its configuration is saved.
//   - a scheduled task file under System32\Tasks: a task outside
//     \Microsoft\ whose writer is untrusted or, when the Task Scheduler
//     itself wrote the file, one that runs a program from outside the
//     system folders, is deleted with schtasks.exe; its definition is
//     saved.
//
// zaafvesper quarantine restore puts each back (a service is re-created
// stopped). Caller holds actMu.
func (r *Responder) persist(e *event.Event, rule string, budget func() *result) result {
	switch {
	case e.Registry != nil && e.Name == event.RegistrySetValue:
		if _, why := winServiceImagePath(e.Registry.Key); why == "" {
			return r.removeService(e, rule, budget)
		}
		return r.removeRunValue(e, rule, budget)
	case e.File != nil:
		return r.removeTask(e, rule, budget)
	}
	return refused(OutcomeFileCheck, ErrFileCheck, "event %s is not a registry value set or a file event", e.Name)
}

// savedValue is the vault content of a registry-value record.
type savedValue struct {
	Hive string `json:"hive"`
	Key  string `json:"key"`
	Name string `json:"name"`
	Type uint32 `json:"type"`
	Data string `json:"data"`
}

func hiveKey(h string) registry.Key {
	if h == "HKU" {
		return registry.USERS
	}
	return registry.LOCAL_MACHINE
}

func (r *Responder) removeRunValue(e *event.Event, rule string, budget func() *result) result {
	if _, res := r.preflight(e, TargetFile, preUntrustedWriter); res != nil {
		return *res
	}
	hive, key, name, why := winRunValue(e.Registry.Key)
	if why != "" {
		return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
	}
	k, err := registry.OpenKey(hiveKey(hive), key, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return refused(OutcomeFileCheck, ErrFileCheck, "open %s\\%s: %v", hive, key, err)
	}
	defer k.Close()
	data, typ, err := k.GetStringValue(name)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return refused(OutcomeFileCheck, ErrFileCheck, "value %q is gone", name)
	case err != nil:
		return refused(OutcomeFileCheck, ErrFileCheck, "value %q is not a string (%v)", name, err)
	case data != e.Registry.Data:
		return refused(OutcomeFileCheck, ErrFileCheck, "value %q changed since the event (now %q)", name, data)
	}
	if res := budget(); res != nil {
		return *res
	}
	if r.cfg.DryRun {
		return result{OutcomeDryRun, fmt.Sprintf("would delete the Run value %s\\%s\\%s (%q)", hive, key, name, data), nil}
	}
	saved, _ := json.Marshal(savedValue{Hive: hive, Key: key, Name: name, Type: typ, Data: data})
	id, err := r.vault().storeData(saved, r.persistRecord(e, rule, persistRunValue, e.Registry.Key, name, len(saved)))
	if err != nil {
		return result{OutcomeError, "vault: " + err.Error(), fmt.Errorf("response: remove_persistence %s: %w", e.Registry.Key, err)}
	}
	if err := k.DeleteValue(name); err != nil {
		return result{OutcomeError, fmt.Sprintf("value saved as %s but not deleted: %v", id, err), fmt.Errorf("response: remove_persistence %s: %w", e.Registry.Key, err)}
	}
	return result{OutcomePersistenceRemoved, fmt.Sprintf("Run value %q deleted (data %q); saved as %s (restore: zaafvesper quarantine restore %s); programs it already started keep running",
		name, data, id, id[:12]), nil}
}

func (r *Responder) vault() Vault {
	return Vault{Dir: r.cfg.VaultDir, RequireRootOwned: r.cfg.RequireRootOwned}
}

func (r *Responder) persistRecord(e *event.Event, rule, kind, orig, label string, size int) QuarantineRecord {
	return QuarantineRecord{Time: r.cfg.Now().UTC(), Action: ActionRemovePersistence, OriginalPath: orig, Size: int64(size),
		Rule: rule, PID: e.Proc.PID, Exe: e.Proc.Exe, Label: label, Kind: kind}
}

// savedService is the vault content of a service record.
type savedService struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	BinaryPath  string   `json:"binary_path"`
	ServiceType uint32   `json:"service_type"`
	StartType   uint32   `json:"start_type"`
	ErrorCtl    uint32   `json:"error_control"`
	Account     string   `json:"account"`
	Description string   `json:"description"`
	Depends     []string `json:"dependencies,omitempty"`
}

func (r *Responder) removeService(e *event.Event, rule string, budget func() *result) result {
	p, res := r.preflight(e, TargetFile, preWriter)
	if res != nil {
		return *res
	}
	// The Service Control Manager writes the key for whoever created the
	// service: then the program the service runs is judged instead.
	if !equalASCIIFold(p.Exe, servicesExe) {
		if why := trustedWriter(p); why != "" {
			return refused(OutcomeWriterNotUntrusted, ErrProtected, "%s", why)
		}
	}
	name, _ := winServiceImagePath(e.Registry.Key)
	if why := protectedService(name); why != "" {
		return refused(OutcomeLabel, ErrLabel, "%s", why)
	}
	m, err := mgr.Connect()
	if err != nil {
		return refused(OutcomeFileCheck, ErrFileCheck, "service control manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return refused(OutcomeFileCheck, ErrFileCheck, "open service %s: %v", name, err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return refused(OutcomeFileCheck, ErrFileCheck, "service %s configuration: %v", name, err)
	}
	img := expandSystemVars(serviceImage(cfg.BinaryPathName), systemRoot)
	switch {
	case cfg.BinaryPathName != e.Registry.Data:
		return refused(OutcomeFileCheck, ErrFileCheck, "service %s now runs %q, the event set %q", name, cfg.BinaryPathName, e.Registry.Data)
	case cfg.ServiceType&windows.SERVICE_WIN32 == 0:
		return refused(OutcomeLabel, ErrLabel, "service %s is a driver (type %#x); drivers are never stopped", name, cfg.ServiceType)
	case systemImage(img):
		return refused(OutcomeWriterNotUntrusted, ErrProtected, "service %s runs a system program (%s)", name, img)
	}
	if res := budget(); res != nil {
		return *res
	}
	if r.cfg.DryRun {
		return result{OutcomeDryRun, fmt.Sprintf("would stop and delete service %s (%q)", name, cfg.BinaryPathName), nil}
	}
	saved, _ := json.Marshal(savedService{Name: name, DisplayName: cfg.DisplayName, BinaryPath: cfg.BinaryPathName, ServiceType: cfg.ServiceType,
		StartType: cfg.StartType, ErrorCtl: cfg.ErrorControl, Account: cfg.ServiceStartName, Description: cfg.Description, Depends: cfg.Dependencies})
	id, err := r.vault().storeData(saved, r.persistRecord(e, rule, persistService, e.Registry.Key, name, len(saved)))
	if err != nil {
		return result{OutcomeError, "vault: " + err.Error(), fmt.Errorf("response: remove_persistence service %s: %w", name, err)}
	}
	var notes []string
	stopped := true
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			notes, stopped = append(notes, "stop failed: "+err.Error()), false
		} else {
			stopped = waitStopped(s, 10*time.Second)
			if !stopped {
				notes = append(notes, "did not stop within 10 s")
			}
		}
	}
	if err := s.Delete(); err != nil {
		return result{OutcomeError, strings.Join(append(notes, fmt.Sprintf("configuration saved as %s, but the service was not deleted: %v", id, err)), "; "),
			fmt.Errorf("response: remove_persistence service %s: %w", name, err)}
	}
	notes = append(notes, fmt.Sprintf("service %s deleted (%q); configuration saved as %s (restore: zaafvesper quarantine restore %s)", name, cfg.BinaryPathName, id, id[:12]))
	if !stopped {
		notes = append(notes, "Windows removes it once its process ends")
		return result{OutcomePartial, strings.Join(notes, "; "), fmt.Errorf("response: remove_persistence service %s: not stopped", name)}
	}
	return result{OutcomePersistenceRemoved, strings.Join(notes, "; "), nil}
}

func waitStopped(s *mgr.Service, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func (r *Responder) schtasks(args ...string) ([]byte, error) {
	return r.cfg.Runner(context.Background(), SchtasksBin, args, nil)
}

func (r *Responder) removeTask(e *event.Event, rule string, budget func() *result) result {
	p, res := r.preflight(e, TargetFile, preWriter)
	if res != nil {
		return *res
	}
	path, b, why := fileTarget(e, TargetFile)
	if why != "" {
		return refused(OutcomeFileCheck, ErrFileCheck, "%s", why)
	}
	name, why := winTaskName(path, tasksDir)
	if why != "" {
		return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
	}
	dirfd, _, f, fi, res := r.openBoundIn(path, b, false, maxTaskBytes, e, tasksDir+`\`)
	if res != nil {
		return *res
	}
	defer closeFD(dirfd)
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTaskBytes+1))
	if err != nil || int64(len(data)) != fi.Size {
		return refused(OutcomeFileCheck, ErrFileCheck, "read the task definition: %v (%d of %d bytes)", err, len(data), fi.Size)
	}
	cmds, err := taskCommands(data)
	if err != nil {
		return refused(OutcomeFileCheck, ErrFileCheck, "%v", err)
	}
	if equalASCIIFold(p.Exe, svchostExe) {
		// The Task Scheduler wrote the file for whoever registered the
		// task: judge the programs the task runs instead.
		untrusted := false
		for _, c := range cmds {
			if !systemImage(expandSystemVars(serviceImage(c), systemRoot)) {
				untrusted = true
			}
		}
		if !untrusted {
			return refused(OutcomeWriterNotUntrusted, ErrProtected, "task %s runs only system programs (%s)", name, strings.Join(cmds, ", "))
		}
	} else if why := trustedWriter(p); why != "" {
		return refused(OutcomeWriterNotUntrusted, ErrProtected, "%s", why)
	}
	if res := budget(); res != nil {
		return *res
	}
	if r.cfg.DryRun {
		return result{OutcomeDryRun, fmt.Sprintf("would delete scheduled task %s (runs %s)", name, strings.Join(cmds, ", ")), nil}
	}
	id, err := r.vault().storeData(data, r.persistRecord(e, rule, persistTask, path, name, len(data)))
	if err != nil {
		return result{OutcomeError, "vault: " + err.Error(), fmt.Errorf("response: remove_persistence task %s: %w", name, err)}
	}
	if _, err := r.schtasks("/Delete", "/TN", name, "/F"); err != nil {
		return result{OutcomeError, fmt.Sprintf("definition saved as %s, but schtasks /Delete failed: %v", id, err), fmt.Errorf("response: remove_persistence task %s: %w", name, err)}
	}
	return result{OutcomePersistenceRemoved, fmt.Sprintf("scheduled task %s deleted (ran %s); definition saved as %s (restore: zaafvesper quarantine restore %s); a run already started keeps running",
		name, strings.Join(cmds, ", "), id, id[:12]), nil}
}

// restoreKind puts back a Run value (only when no value of that name
// exists), a service (created stopped) or a scheduled task (schtasks
// /Create /XML from a copy in the vault directory).
func restoreKind(rec QuarantineRecord, data []byte, vaultDir, id string) ([]string, error) {
	switch rec.Kind {
	case persistRunValue:
		var v savedValue
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		if _, _, _, why := winRunValue(v.Hive + `\` + v.Key + `\` + v.Name); why != "" {
			return nil, fmt.Errorf("saved value: %s", why)
		}
		k, err := registry.OpenKey(hiveKey(v.Hive), v.Key, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
		if err != nil {
			return nil, err
		}
		defer k.Close()
		if _, _, err := k.GetValue(v.Name, nil); err == nil {
			return nil, fmt.Errorf("value %q exists; delete it first", v.Name)
		}
		if v.Type == registry.EXPAND_SZ {
			return nil, k.SetExpandStringValue(v.Name, v.Data)
		}
		return nil, k.SetStringValue(v.Name, v.Data)
	case persistService:
		var v savedService
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		if !serviceNameRe.MatchString(v.Name) || protectedService(v.Name) != "" {
			return nil, fmt.Errorf("saved service name %q refused", v.Name)
		}
		m, err := mgr.Connect()
		if err != nil {
			return nil, err
		}
		defer m.Disconnect()
		h, err := windows.CreateService(m.Handle, windows.StringToUTF16Ptr(v.Name), windows.StringToUTF16Ptr(v.DisplayName),
			windows.SERVICE_ALL_ACCESS, v.ServiceType, v.StartType, v.ErrorCtl, windows.StringToUTF16Ptr(v.BinaryPath),
			nil, nil, nil, accountPtr(v.Account), nil)
		if err != nil {
			return nil, fmt.Errorf("create service %s: %w", v.Name, err)
		}
		_ = windows.CloseServiceHandle(h)
		return []string{"service " + v.Name + " re-created, not started (a password the account needed is not restored)"}, nil
	case persistTask:
		name, why := winTaskName(rec.OriginalPath, tasksDir)
		if why != "" || name != rec.Label {
			return nil, fmt.Errorf("saved task %q refused: %s", rec.Label, why)
		}
		tmp := filepath.Join(vaultDir, ".restore-"+id[:16]+".xml")
		if err := writeNewFile(tmp, data); err != nil {
			return nil, err
		}
		defer windows.DeleteFile(windows.StringToUTF16Ptr(tmp))
		if out, err := RunPinned(context.Background(), SchtasksBin, []string{"/Create", "/TN", name, "/XML", tmp}, nil); err != nil {
			return nil, fmt.Errorf("schtasks /Create: %v %s", err, strings.TrimSpace(string(out)))
		}
		return []string{"scheduled task " + name + " re-created (a stored password is not restored)"}, nil
	}
	return nil, fmt.Errorf("record kind %q cannot be restored", rec.Kind)
}

func accountPtr(a string) *uint16 {
	if a == "" {
		return nil
	}
	return windows.StringToUTF16Ptr(a)
}

// writeNewFile creates path (it must not exist) inside the private vault
// directory with data.
func writeNewFile(path string, data []byte) error {
	fd, err := createFile(path, windows.GENERIC_WRITE, 0, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		return err
	}
	h := handle(fd)
	defer windows.CloseHandle(h)
	var n uint32
	return windows.WriteFile(h, data, &n, nil)
}
