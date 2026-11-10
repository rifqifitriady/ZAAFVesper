package sigma

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// tactics maps Sigma ATT&CK tactic tags (attack.<name>) to ZAAFVesper's
// tactic ids and names. Names follow the ATT&CK release the built-in rules
// use (docs/rules.md): TA0005 is "Stealth" there.
var tactics = map[string][2]string{
	"reconnaissance":       {"TA0043", "Reconnaissance"},
	"resource-development": {"TA0042", "Resource Development"},
	"initial-access":       {"TA0001", "Initial Access"},
	"execution":            {"TA0002", "Execution"},
	"persistence":          {"TA0003", "Persistence"},
	"privilege-escalation": {"TA0004", "Privilege Escalation"},
	"defense-evasion":      {"TA0005", "Stealth"},
	"stealth":              {"TA0005", "Stealth"},
	"defense-impairment":   {"TA0112", "Defense Impairment"},
	"credential-access":    {"TA0006", "Credential Access"},
	"discovery":            {"TA0007", "Discovery"},
	"lateral-movement":     {"TA0008", "Lateral Movement"},
	"collection":           {"TA0009", "Collection"},
	"exfiltration":         {"TA0010", "Exfiltration"},
	"command-and-control":  {"TA0011", "Command and Control"},
	"impact":               {"TA0040", "Impact"},
}

// revoked maps technique ids that SigmaHQ still uses but the ATT&CK release
// of the built-in rules revoked, to their replacements: every revoked-by
// relationship for T1562.* and T1070.00[12] in that release's
// enterprise-attack.json (Atomic Red Team a0e3f9bc). Other ids are kept as
// given; the coverage report's --attack check catches any that are revoked.
var revoked = map[string]string{
	"T1070.001": "T1685.005",
	"T1070.002": "T1685.006",
	"T1562":     "T1685",
	"T1562.001": "T1685",
	"T1562.002": "T1685.001",
	"T1562.003": "T1690",
	"T1562.004": "T1686",
	"T1562.006": "T1685",
	"T1562.007": "T1686.001",
	"T1562.008": "T1685.002",
	"T1562.009": "T1688",
	"T1562.010": "T1689",
	"T1562.011": "T1685.003",
	"T1562.012": "T1685.004",
	"T1562.013": "T1686.002",
}

// impairment is the Defense Impairment (TA0112) family the revoked ids
// moved into.
func impairment(id string) bool {
	for _, p := range []string{"T1685", "T1686", "T1688", "T1689", "T1690"} {
		if id == p || strings.HasPrefix(id, p+".") {
			return true
		}
	}
	return false
}

var techTag = regexp.MustCompile(`^t\d{4}(\.\d{3})?$`)

type attack struct {
	labels map[string]string
	notes  []string
}

// attackLabels turns Sigma tags into technique.id, tactic.id and
// tactic.name labels.
func attackLabels(tags []string) attack {
	out := attack{labels: map[string]string{}}
	var techs, tacIDs []string
	tacName := map[string]string{}
	seenT, seenA := map[string]bool{}, map[string]bool{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !strings.HasPrefix(t, "attack.") {
			continue
		}
		v := strings.TrimPrefix(t, "attack.")
		if techTag.MatchString(v) {
			id := strings.ToUpper(v)
			if cur, ok := revoked[id]; ok {
				out.notes = append(out.notes, fmt.Sprintf("ATT&CK %s is revoked; labelled %s", id, cur))
				id = cur
			}
			if !seenT[id] {
				seenT[id] = true
				techs = append(techs, id)
			}
			continue
		}
		if ta, ok := tactics[strings.ReplaceAll(v, "_", "-")]; ok && !seenA[ta[0]] {
			seenA[ta[0]] = true
			tacIDs = append(tacIDs, ta[0])
			tacName[ta[0]] = ta[1]
		}
	}
	// Techniques moved into Defense Impairment take that tactic; Stealth is
	// dropped when no remaining technique needs it.
	allImp, anyImp := len(techs) > 0, false
	for _, id := range techs {
		if impairment(id) {
			anyImp = true
		} else {
			allImp = false
		}
	}
	if anyImp && !seenA["TA0112"] {
		tacIDs = append(tacIDs, "TA0112")
		tacName["TA0112"] = "Defense Impairment"
		if allImp && seenA["TA0005"] {
			tacIDs = remove(tacIDs, "TA0005")
		}
	}
	sort.Strings(tacIDs)
	if len(techs) > 0 {
		out.labels["technique.id"] = strings.Join(techs, ", ")
	}
	if len(tacIDs) > 0 {
		names := make([]string, len(tacIDs))
		for i, id := range tacIDs {
			names[i] = tacName[id]
		}
		out.labels["tactic.id"] = strings.Join(tacIDs, ", ")
		out.labels["tactic.name"] = strings.Join(names, ", ")
	}
	return out
}

func remove(ss []string, x string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != x {
			out = append(out, s)
		}
	}
	return out
}
