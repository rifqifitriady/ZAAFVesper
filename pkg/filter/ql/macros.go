package ql

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/nofollow"
	"go.yaml.in/yaml/v3"
)

// MaxMacroFileSize bounds a macro file read from disk.
const MaxMacroFileSize = 4 << 20

type macroExpr struct {
	expr string
	file string
}

// Macros holds expression macros and list macros.
type Macros struct {
	exprs map[string]macroExpr
	lists map[string][]Lit
	files map[string]string // name -> defining file, for duplicate errors
}

// NewMacros returns an empty macro set.
func NewMacros() *Macros {
	return &Macros{exprs: map[string]macroExpr{}, lists: map[string][]Lit{}, files: map[string]string{}}
}

var macroName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func (m *Macros) checkName(name, file string) error {
	if !macroName.MatchString(name) {
		return fmt.Errorf("invalid macro name %q (use lower_snake_case)", name)
	}
	if isReserved(name) {
		return fmt.Errorf("macro name %q is a reserved word", name)
	}
	if _, ok := event.LookupField(name); ok {
		return fmt.Errorf("macro name %q collides with a field", name)
	}
	if prev, ok := m.files[name]; ok {
		if prev == "" {
			prev = "an earlier definition"
		}
		return fmt.Errorf("macro %q already defined in %s", name, prev)
	}
	return nil
}

// AddExpr adds an expression macro. The expression is checked when it is
// first expanded and by Validate.
func (m *Macros) AddExpr(name, expr string) error {
	return m.addExpr(name, expr, "")
}

func (m *Macros) addExpr(name, expr, file string) error {
	if err := m.checkName(name, file); err != nil {
		return err
	}
	if expr == "" {
		return fmt.Errorf("macro %q has an empty expr", name)
	}
	m.exprs[name] = macroExpr{expr: expr, file: file}
	m.files[name] = file
	return nil
}

// AddList adds a list macro. Items must all be strings or all integers.
func (m *Macros) AddList(name string, items []any) error {
	return m.addList(name, items, "")
}

func (m *Macros) addList(name string, items []any, file string) error {
	if err := m.checkName(name, file); err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("list %q is empty", name)
	}
	lits := make([]Lit, 0, len(items))
	for i, it := range items {
		switch v := it.(type) {
		case string:
			lits = append(lits, Lit{Kind: LitString, S: v})
		case int:
			lits = append(lits, Lit{Kind: LitInt, I: int64(v)})
		case int64:
			lits = append(lits, Lit{Kind: LitInt, I: v})
		default:
			return fmt.Errorf("list %q item %d: unsupported type %T (strings or integers only)", name, i, it)
		}
		if lits[i].Kind != lits[0].Kind {
			return fmt.Errorf("list %q mixes strings and integers", name)
		}
	}
	m.lists[name] = lits
	m.files[name] = file
	return nil
}

// Names returns all macro names, sorted.
func (m *Macros) Names() []string {
	out := make([]string, 0, len(m.files))
	for n := range m.files {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Validate compiles every expression macro, reporting all errors.
func (m *Macros) Validate() error {
	var errs []error
	for _, n := range m.Names() {
		def, ok := m.exprs[n]
		if !ok {
			continue
		}
		if _, err := Compile(def.expr, m); err != nil {
			where := def.file
			if where == "" {
				where = "macros"
			}
			errs = append(errs, fmt.Errorf("%s: macro %q: %w", where, n, err))
		}
	}
	return errors.Join(errs...)
}

type macroEntry struct {
	Macro       string `yaml:"macro"`
	Expr        string `yaml:"expr"`
	List        string `yaml:"list"`
	Items       []any  `yaml:"items"`
	Description string `yaml:"description"`
}

// ReadFunc reads one macro file. ZAAFVesper passes config.SecureRead so that a
// root process checks ownership on the same descriptor it parses.
type ReadFunc func(path string, max int64) ([]byte, error)

// readNoFollow is the default ReadFunc: no symlinks, regular files only,
// bounded size, read from the descriptor that was checked.
func readNoFollow(path string, max int64) ([]byte, error) {
	f, err := nofollow.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: file larger than %d bytes", path, max)
	}
	return data, nil
}

// LoadMacros reads macro files (YAML lists of `macro:`/`expr:` and
// `list:`/`items:` entries) and validates every expression macro.
func LoadMacros(paths ...string) (*Macros, error) {
	return LoadMacrosWith(readNoFollow, paths...)
}

// LoadMacrosWith is LoadMacros with a custom file reader.
func LoadMacrosWith(read ReadFunc, paths ...string) (*Macros, error) {
	m := NewMacros()
	var errs []error
	for _, path := range paths {
		data, err := read(path, MaxMacroFileSize)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := m.loadBytes(path, data); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Macros) loadBytes(path string, data []byte) error {
	var entries []macroEntry
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&entries); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	for i, e := range entries {
		var err error
		switch {
		case e.Macro != "" && e.List != "":
			err = fmt.Errorf("entry %d defines both macro and list", i+1)
		case e.Macro != "":
			if e.Items != nil {
				err = fmt.Errorf("macro %q: items belong to a list entry", e.Macro)
			} else {
				err = m.addExpr(e.Macro, e.Expr, path)
			}
		case e.List != "":
			if e.Expr != "" {
				err = fmt.Errorf("list %q: expr belongs to a macro entry", e.List)
			} else {
				err = m.addList(e.List, e.Items, path)
			}
		default:
			err = fmt.Errorf("entry %d has neither macro nor list", i+1)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}
