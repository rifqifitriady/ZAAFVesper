package ebpf

import (
	"errors"
	"strconv"
	"strings"
)

// The kernel side copies at most the first 512 bytes of a UDP datagram
// sent to port 53. parseDNSQuery reads the question from it. The bytes are
// whatever the sending process wrote, so the parser trusts nothing: it
// rejects responses, compression pointers in a question (a query never
// needs them), labels longer than 63 bytes, names longer than 253 and
// non-printable bytes.

var errNotQuery = errors.New("not a DNS query")

// dnsTypes names the common query types; others are reported as TYPE<n>
// (RFC 3597).
var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 52: "TLSA",
	64: "SVCB", 65: "HTTPS", 255: "ANY", 257: "CAA",
}

func dnsTypeName(t uint16) string {
	if n, ok := dnsTypes[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// parseDNSQuery returns the first question's name (lower-case, no trailing
// dot) and type.
func parseDNSQuery(b []byte) (name, qtype string, err error) {
	if len(b) < 12 {
		return "", "", errNotQuery
	}
	flags := uint16(b[2])<<8 | uint16(b[3])
	if flags&0x8000 != 0 { // QR: a response
		return "", "", errNotQuery
	}
	if opcode := (flags >> 11) & 0xf; opcode != 0 { // standard query only
		return "", "", errNotQuery
	}
	if qd := uint16(b[4])<<8 | uint16(b[5]); qd == 0 {
		return "", "", errNotQuery
	}
	var sb strings.Builder
	pos := 12
	for {
		if pos >= len(b) {
			return "", "", errNotQuery
		}
		l := int(b[pos])
		pos++
		if l == 0 {
			break
		}
		if l > 63 || pos+l > len(b) {
			return "", "", errNotQuery
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range b[pos : pos+l] {
			if c < 0x21 || c > 0x7e {
				return "", "", errNotQuery
			}
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			sb.WriteByte(c)
		}
		if sb.Len() > 253 {
			return "", "", errNotQuery
		}
		pos += l
	}
	if pos+4 > len(b) {
		return "", "", errNotQuery
	}
	t := uint16(b[pos])<<8 | uint16(b[pos+1])
	if sb.Len() == 0 {
		return ".", dnsTypeName(t), nil
	}
	return sb.String(), dnsTypeName(t), nil
}
