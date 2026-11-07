package ps

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Bounds on what bootstrap copies per process. The byte budgets match the
// eslogger decoder's (64 KiB of argv, 16 KiB of environment per process).
const (
	bootMaxArgs    = 1024
	bootMaxEnv     = 512
	bootArgsBudget = 64 << 10
	bootEnvBudget  = 16 << 10
	bootMaxCmdline = 64 << 10
)

// parseProcArgs decodes a kern.procargs2 buffer:
//
//	int32 argc | exec_path \0 | \0 padding | argv[0..argc) \0-separated | env \0-separated | ...
//
// Only bytes within the budgets are converted to strings, so a huge argv
// never ends up retained. It never panics on short or malformed input.
func parseProcArgs(b []byte) (exe string, args []string, env map[string]string) {
	if len(b) < 4 {
		return "", nil, nil
	}
	argc := int(int32(binary.LittleEndian.Uint32(b[:4])))
	b = b[4:]
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b[:min(len(b), 4096)]), nil, nil
	}
	exe = string(b[:min(i, 4096)])
	b = b[i:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	next := func() ([]byte, bool) {
		if len(b) == 0 {
			return nil, false
		}
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			seg := b
			b = nil
			return seg, true
		}
		seg := b[:j]
		b = b[j+1:]
		return seg, true
	}
	budget := bootArgsBudget
	for n := 0; n < argc && n < bootMaxArgs; n++ {
		seg, ok := next()
		if !ok {
			break
		}
		if budget <= 0 {
			continue // keep consuming argv so the environment parses correctly
		}
		if len(seg) > budget {
			seg = seg[:budget]
		}
		budget -= len(seg)
		args = append(args, string(seg))
	}
	budget = bootEnvBudget
	for len(env) < bootMaxEnv && budget > 0 {
		seg, ok := next()
		if !ok || len(seg) == 0 {
			break
		}
		k, v, found := bytes.Cut(seg, []byte("="))
		if !found || len(k) == 0 {
			continue
		}
		if len(k)+len(v) > budget {
			if len(k) >= budget {
				break
			}
			v = v[:budget-len(k)]
		}
		budget -= len(k) + len(v)
		if env == nil {
			env = map[string]string{}
		}
		env[string(k)] = string(v)
	}
	return exe, args, env
}

func joinCap(args []string, limit int) string {
	s := strings.Join(args, " ")
	if len(s) > limit {
		s = strings.Clone(s[:limit])
	}
	return s
}
