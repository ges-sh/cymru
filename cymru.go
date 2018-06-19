package cymru

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const shortTimeForm = "2006-01-02"

// TXT contains information about DNS TXT record
type TXT struct {
	AS        string
	IP        net.IP
	CIDR      *net.IPNet
	Country   string
	RIR       string
	CreatedAt time.Time
}

const origin = "origin.asn.cymru.com"

// Lookup returns TXT data of provided dns record
func Lookup(addr string) (*TXT, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return nil, errors.New("not IPv4")
	}

	reverseIP(ip)

	dns := ip.String() + "." + origin

	info, err := net.LookupTXT(dns)
	if err != nil {
		return nil, err
	}
	if len(info) < 1 {
		return nil, errors.New("no dns info")
	}

	splitTXT := splitFuncs(info[0], "|", strings.TrimSpace)
	if len(splitTXT) < 5 {
		return nil, fmt.Errorf("invalid TXT format %v", splitTXT)
	}

	ip, ipNet, err := net.ParseCIDR(splitTXT[1])
	if err != nil {
		return nil, err
	}

	createdAt, err := time.Parse(shortTimeForm, splitTXT[4])
	if err != nil {
		return nil, err
	}
	txt := &TXT{
		AS:        splitTXT[0],
		IP:        ip,
		CIDR:      ipNet,
		Country:   splitTXT[2],
		RIR:       splitTXT[3],
		CreatedAt: createdAt,
	}

	return txt, nil
}

func reverseIP(ip net.IP) {
	ip[0], ip[3] = ip[3], ip[0]
	ip[1], ip[2] = ip[2], ip[1]
}

// ASNTXT contains TXT data gathered from ASN lookup
type ASNTXT struct {
	ASN       string
	Country   string
	RIR       string
	CreatedAt time.Time
	Provider  string
}

const asnOrigin = "asn.cymru.com"

// LookupASN makes ASN lookup
func LookupASN(as string) (*ASNTXT, error) {
	asn := as + "." + asnOrigin
	info, err := net.LookupTXT(asn)
	if err != nil {
		return nil, err
	}
	if len(info) < 1 {
		return nil, errors.New("no dns info")
	}
	splitTXT := splitFuncs(info[0], "|", strings.TrimSpace)
	if len(splitTXT) < 5 {
		return nil, fmt.Errorf("invalid TXT format %v", splitTXT)
	}

	createdAt, err := time.Parse(shortTimeForm, splitTXT[3])
	if err != nil {
		return nil, err
	}

	asntxt := &ASNTXT{
		ASN:       splitTXT[0],
		Country:   splitTXT[1],
		RIR:       splitTXT[2],
		CreatedAt: createdAt,
		Provider:  splitTXT[4],
	}
	return asntxt, nil
}

// splitFuncs allows to provide additional funcs fs for strings.Split,
// which are invoked for every element of splitted string
func splitFuncs(s, sep string, fs ...func(string) string) []string {
	split := strings.Split(s, sep)
	for i := range split {
		for _, v := range fs {
			split[i] = v(split[i])
		}
	}
	return split
}
