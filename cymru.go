package cymru

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const shortTimeForm = "2006-01-02"

// IPInfo contains information about DNS IPInfo record
type IPInfo struct {
	AS        string
	CIDR      *net.IPNet
	Country   string
	Register  string
	CreatedAt time.Time
}

const origin = "origin.asn.cymru.com"

// LookupIP returns ip info. It accepts ip address in format "xxx.xxx.xxx.xxx"
func LookupIP(addr string) (IPInfo, error) {
	var ipInfo IPInfo
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return ipInfo, errors.New("not IPv4")
	}

	reverseIP(ip)

	dns := ip.String() + "." + origin

	info, err := net.LookupTXT(dns)
	if err != nil {
		return ipInfo, err
	}
	if len(info) < 1 {
		return ipInfo, errors.New("no dns info")
	}

	splitTXT := strings.Split(info[0], " | ")
	if len(splitTXT) < 5 {
		return ipInfo, fmt.Errorf("invalid TXT format %v", splitTXT)
	}

	_, ipInfo.CIDR, err = net.ParseCIDR(splitTXT[1])
	if err != nil {
		return ipInfo, err
	}

	ipInfo.CreatedAt, err = time.Parse(shortTimeForm, splitTXT[4])
	if err != nil {
		return ipInfo, err
	}

	ipInfo.AS = splitTXT[0]
	ipInfo.Country = splitTXT[2]
	ipInfo.Register = splitTXT[4]

	return ipInfo, nil
}

func reverseIP(ip net.IP) {
	ip[0], ip[3] = ip[3], ip[0]
	ip[1], ip[2] = ip[2], ip[1]
}

// ASInfo contains data gathered from AS lookup
type ASInfo struct {
	AS        string
	Country   string
	Register  string
	CreatedAt time.Time
	Provider  string
}

const asnOrigin = "asn.cymru.com"

// LookupAS returns as info. It accepts as name in format "ASXXXXX"
func LookupAS(as string) (ASInfo, error) {
	var asInfo ASInfo

	asn := as + "." + asnOrigin
	info, err := net.LookupTXT(asn)
	if err != nil {
		return asInfo, err
	}
	if len(info) < 1 {
		return asInfo, errors.New("no dns info")
	}
	splitTXT := strings.Split(info[0], " | ")
	if len(splitTXT) < 5 {
		return asInfo, fmt.Errorf("invalid TXT format %v", splitTXT)
	}

	asInfo.CreatedAt, err = time.Parse(shortTimeForm, splitTXT[3])
	if err != nil {
		return asInfo, err
	}

	asInfo.AS = splitTXT[0]
	asInfo.Country = splitTXT[1]
	asInfo.Register = splitTXT[2]
	asInfo.Provider = splitTXT[4]

	return asInfo, nil
}
