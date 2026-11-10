package response

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf16"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// maxPlistBytes caps a launch item plist read by remove_persistence.
const maxPlistBytes = 1 << 20

// OwnLabel is ZAAFVesper's own LaunchDaemon label: never booted out.
const OwnLabel = "com.rifqifitriady.zaafvesper"

// labelRe is the launchd labels remove_persistence accepts: letters,
// digits, dot, dash and underscore, starting with a letter or digit. The
// label becomes part of a launchctl service target (domain/label), so "/"
// and anything else is refused.
var labelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// RemovePersistence removes the persistence the event's process installed,
// after its event: on macOS a launch item plist (persistence_darwin.go), on
// Linux a systemd unit, a cron file or a shell rc file
// (persistence_linux.go), on Windows a Run/RunOnce value, a service or a
// scheduled task (persistence_windows.go). The writer must be untrusted and
// every quarantine guard rail applies; what the item already did stays
// done. The removed item is kept in the vault (zaafvesper quarantine
// restore).
func (r *Responder) RemovePersistence(e *event.Event, rule, reason string) error {
	var run func() error
	run = func() error {
		return r.retryOnLimit(fileRetryKey(ActionRemovePersistence, rule, e, TargetFile), rule, reason, r.removePersistence(e, rule, reason), run)
	}
	return run()
}

func (r *Responder) removePersistence(e *event.Event, rule, reason string) error {
	p := procOf(e)
	d := Decision{Action: ActionRemovePersistence, PID: p.PID, Target: TargetFile, Name: p.Name, Exe: p.Exe, Reason: reason}
	switch {
	case e != nil && e.File != nil:
		d.Path, _, _ = fileTarget(e, TargetFile)
	case e != nil && e.Registry != nil:
		d.Path = e.Registry.Key
	}
	return r.act(d, rule, func(budget func() *result) result {
		if e == nil {
			return refused(OutcomeFileCheck, ErrFileCheck, "no event")
		}
		return r.persist(e, rule, budget)
	})
}

// PlistLabel returns the top-level Label string of an XML or binary
// (bplist00) property list. A missing, non-string or repeated Label is an
// error.
func PlistLabel(b []byte) (string, error) {
	if bytes.HasPrefix(b, []byte("bplist00")) {
		return bplistLabel(b)
	}
	return xmlPlistLabel(b)
}

var errNoLabel = errors.New("no Label string at the top level")

// xmlPlistLabel reads <plist><dict>...<key>Label</key><string>x</string>.
func xmlPlistLabel(b []byte) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	depth, tokens := 0, 0
	inTopDict := false
	var label string
	found := 0
	expectLabel := false
	for {
		tokens++
		if tokens > 200000 {
			return "", errors.New("plist too complex")
		}
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("xml plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 1 && t.Name.Local != "plist":
				return "", errors.New("not a plist")
			case depth == 2:
				if t.Name.Local != "dict" {
					return "", errors.New("top level is not a dict")
				}
				inTopDict = true
			case depth == 3 && inTopDict && t.Name.Local == "key":
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return "", err
				}
				depth--
				expectLabel = k == "Label"
			case depth == 3 && inTopDict:
				if expectLabel {
					found++
					if t.Name.Local != "string" {
						return "", errors.New("Label is not a string")
					}
					if err := dec.DecodeElement(&label, &t); err != nil {
						return "", err
					}
					depth--
				}
				expectLabel = false
			}
		case xml.EndElement:
			depth--
		}
	}
	switch found {
	case 0:
		return "", errNoLabel
	case 1:
		return label, nil
	}
	return "", errors.New("Label appears more than once")
}

// bplistLabel reads the top-level Label of a binary property list.
func bplistLabel(b []byte) (string, error) {
	if len(b) < 8+32 {
		return "", errors.New("bplist: too short")
	}
	tr := b[len(b)-32:]
	offSize, refSize := int(tr[6]), int(tr[7])
	numObj := binary.BigEndian.Uint64(tr[8:16])
	top := binary.BigEndian.Uint64(tr[16:24])
	tableOff := binary.BigEndian.Uint64(tr[24:32])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObj == 0 || numObj > 1<<20 ||
		top >= numObj || tableOff >= uint64(len(b)-32) || tableOff+numObj*uint64(offSize) > uint64(len(b)-32) {
		return "", errors.New("bplist: bad trailer")
	}
	readN := func(p []byte) uint64 {
		var v uint64
		for _, c := range p {
			v = v<<8 | uint64(c)
		}
		return v
	}
	objOff := func(ref uint64) (int, error) {
		if ref >= numObj {
			return 0, errors.New("bplist: bad object reference")
		}
		o := readN(b[tableOff+ref*uint64(offSize) : tableOff+(ref+1)*uint64(offSize)])
		if o < 8 || o >= tableOff {
			return 0, errors.New("bplist: bad object offset")
		}
		return int(o), nil
	}
	// length decodes the count of an object at off (marker low nibble or a
	// following int object) and returns it with the offset of the payload.
	length := func(off int) (int, int, error) {
		n := int(b[off] & 0x0f)
		off++
		if n != 0x0f {
			return n, off, nil
		}
		if off >= len(b) || b[off]&0xf0 != 0x10 {
			return 0, 0, errors.New("bplist: bad length")
		}
		w := 1 << (b[off] & 0x0f)
		if w > 8 || off+1+w > len(b) {
			return 0, 0, errors.New("bplist: bad length")
		}
		v := readN(b[off+1 : off+1+w])
		if v > uint64(len(b)) {
			return 0, 0, errors.New("bplist: bad length")
		}
		return int(v), off + 1 + w, nil
	}
	str := func(ref uint64) (string, bool, error) {
		off, err := objOff(ref)
		if err != nil {
			return "", false, err
		}
		kind := b[off] & 0xf0
		if kind != 0x50 && kind != 0x60 {
			return "", false, nil
		}
		n, p, err := length(off)
		if err != nil {
			return "", false, err
		}
		if kind == 0x50 {
			if p+n > int(tableOff) {
				return "", false, errors.New("bplist: string out of range")
			}
			return string(b[p : p+n]), true, nil
		}
		if p+2*n > int(tableOff) {
			return "", false, errors.New("bplist: string out of range")
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[p+2*i:])
		}
		return string(utf16.Decode(u)), true, nil
	}
	off, err := objOff(top)
	if err != nil {
		return "", err
	}
	if b[off]&0xf0 != 0xd0 {
		return "", errors.New("bplist: top level is not a dict")
	}
	n, p, err := length(off)
	if err != nil {
		return "", err
	}
	if p+2*n*refSize > int(tableOff) {
		return "", errors.New("bplist: dict out of range")
	}
	ref := func(i int) uint64 { return readN(b[p+i*refSize : p+(i+1)*refSize]) }
	found := 0
	var label string
	for i := 0; i < n; i++ {
		k, ok, err := str(ref(i))
		if err != nil {
			return "", err
		}
		if !ok || k != "Label" {
			continue
		}
		v, ok, err := str(ref(n + i))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("Label is not a string")
		}
		found++
		label = v
	}
	switch found {
	case 0:
		return "", errNoLabel
	case 1:
		return label, nil
	}
	return "", errors.New("Label appears more than once")
}
