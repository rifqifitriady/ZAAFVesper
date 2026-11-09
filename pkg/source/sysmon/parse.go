package sysmon

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Bounds on one event. A Sysmon command line is at most 32 767 UTF-16 code
// units; escaped as XML ("&amp;" is 5 bytes) and with the parent's command
// line in the same event 1, a legitimate event stays below 400 KiB, so
// MaxEventBytes leaves a wide margin. MaxFieldBytes bounds the decoded value.
const (
	// MaxEventBytes bounds the XML of one event (UTF-8).
	MaxEventBytes = 1 << 20
	// MaxFieldBytes bounds one <Data> value.
	MaxFieldBytes = 128 << 10
	maxDataItems  = 128
	maxDepth      = 8
	maxTokens     = 4096
)

// Errors.
var (
	ErrTooLarge    = errors.New("sysmon: event larger than MaxEventBytes")
	ErrNotSysmon   = errors.New("sysmon: not a Sysmon event (unknown provider)")
	ErrMalformed   = errors.New("sysmon: malformed event XML")
	ErrDuplicate   = errors.New("sysmon: duplicate <Data> name")
	ErrUnsupported = errors.New("sysmon: event id not mapped")
)

// Record is the parsed form of one rendered event (the System header fields
// ZAAFVesper uses and the named EventData values).
type Record struct {
	Provider string
	// ExecPID is System/Execution/@ProcessID and UserID System/Security/@UserID
	// (Windows; Sysmon for Linux writes @UserId): who wrote the event, as the
	// event log recorded it. The Windows source checks them (Sysmon's service
	// process, LocalSystem); see pkg/source/winevt.
	ExecPID    uint32
	UserID     string
	EventID    int
	Version    int
	RecordID   uint64
	Computer   string
	SystemTime time.Time
	Data       map[string]string
}

// Parse parses one event as rendered by EvtRender(EvtRenderEventXml) on
// Windows, or as Sysmon for Linux writes it to syslog. It is a strict,
// bounded tokenizer: at most MaxEventBytes, nesting depth 8, 4096 tokens,
// 128 <Data> items of at most MaxFieldBytes each, no duplicate <Data> names
// (two values for one field would let an event say two things), UTF-8 only
// (an XML declaration naming another encoding is refused), and no DTD:
// encoding/xml never fetches external entities and knows only the five
// predefined ones, so entity expansion attacks do not apply.
//
// Characters XML forbids (C0 controls other than tab, CR and LF, U+FFFE,
// U+FFFF, invalid UTF-8, and character references to any of them) do not
// fail the event: they are replaced by U+FFFD first (Sanitize), so a command
// line with a control character cannot make an event disappear.
//
// Each System header element ZAAFVesper reads, and System and EventData
// themselves, may appear only once.
func Parse(raw []byte) (*Record, error) {
	if len(raw) > MaxEventBytes {
		return nil, ErrTooLarge
	}
	raw = Sanitize(raw)
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	r := &Record{Data: map[string]string{}}
	var stack []string
	var text strings.Builder
	dataName, inData, sawRoot := "", false, false
	tokens := 0
	seen := map[string]bool{}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if tokens++; tokens > maxTokens {
			return nil, fmt.Errorf("%w: too many XML tokens", ErrMalformed)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if len(stack) == 0 {
				if name != "Event" || sawRoot {
					return nil, fmt.Errorf("%w: root element %q", ErrMalformed, name)
				}
				sawRoot = true
			}
			if inData {
				return nil, fmt.Errorf("%w: element inside <Data>", ErrMalformed)
			}
			stack = append(stack, name)
			if len(stack) > maxDepth {
				return nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, maxDepth)
			}
			text.Reset()
			path := strings.Join(stack, "/")
			if once[path] {
				if seen[path] {
					return nil, fmt.Errorf("%w: repeated %s", ErrMalformed, path)
				}
				seen[path] = true
			}
			switch path {
			case "Event/System/Execution":
				if n, err := strconv.ParseUint(attr(t, "ProcessID"), 10, 32); err == nil {
					r.ExecPID = uint32(n)
				}
			case "Event/System/Security":
				r.UserID = attr(t, "UserID")
				if r.UserID == "" {
					r.UserID = attr(t, "UserId")
				}
			case "Event/System/Provider":
				r.Provider = attr(t, "Name")
			case "Event/System/TimeCreated":
				if ts, err := time.Parse(time.RFC3339Nano, attr(t, "SystemTime")); err == nil {
					r.SystemTime = ts.UTC()
				}
			case "Event/EventData/Data":
				dataName, inData = attr(t, "Name"), true
				if len(r.Data) >= maxDataItems {
					return nil, fmt.Errorf("%w: more than %d <Data> items", ErrMalformed, maxDataItems)
				}
			}
		case xml.CharData:
			if len(stack) > 0 && text.Len()+len(t) <= MaxFieldBytes {
				text.Write(t)
			} else if len(stack) > 0 {
				return nil, fmt.Errorf("%w: field longer than %d bytes", ErrMalformed, MaxFieldBytes)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("%w: unbalanced end element", ErrMalformed)
			}
			path := strings.Join(stack, "/")
			v := text.String()
			switch path {
			case "Event/System/EventID":
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil || n < 0 || n > 65535 {
					return nil, fmt.Errorf("%w: EventID %q", ErrMalformed, v)
				}
				r.EventID = n
			case "Event/System/Version":
				r.Version, _ = strconv.Atoi(strings.TrimSpace(v))
			case "Event/System/EventRecordID":
				r.RecordID, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			case "Event/System/Computer":
				r.Computer = v
			case "Event/EventData/Data":
				if dataName != "" {
					if _, dup := r.Data[dataName]; dup {
						return nil, fmt.Errorf("%w: %q", ErrDuplicate, dataName)
					}
					r.Data[dataName] = v
				}
				dataName, inData = "", false
			}
			stack = stack[:len(stack)-1]
			text.Reset()
		case xml.ProcInst:
			if t.Target == "xml" {
				if enc := procInstEncoding(t.Inst); enc != "" && !strings.EqualFold(enc, "utf-8") {
					return nil, fmt.Errorf("%w: encoding %q (UTF-8 only)", ErrMalformed, enc)
				}
			}
		case xml.Directive:
			return nil, fmt.Errorf("%w: DTD or directive not allowed", ErrMalformed)
		}
	}
	if !sawRoot || len(stack) != 0 {
		return nil, fmt.Errorf("%w: incomplete event", ErrMalformed)
	}
	if _, ok := providers[r.Provider]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotSysmon, r.Provider)
	}
	return r, nil
}

// once lists the elements that may appear only once in an event.
var once = map[string]bool{
	"Event/System": true, "Event/EventData": true,
	"Event/System/Provider": true, "Event/System/EventID": true, "Event/System/Version": true,
	"Event/System/TimeCreated": true, "Event/System/EventRecordID": true, "Event/System/Execution": true,
	"Event/System/Computer": true, "Event/System/Security": true,
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func procInstEncoding(inst []byte) string {
	s := string(inst)
	i := strings.Index(s, "encoding=")
	if i < 0 {
		return ""
	}
	s = s[i+len("encoding="):]
	if len(s) < 2 {
		return "?"
	}
	q := s[0]
	if q != '"' && q != '\'' {
		return "?"
	}
	end := strings.IndexByte(s[1:], q)
	if end < 0 {
		return "?"
	}
	return s[1 : 1+end]
}
