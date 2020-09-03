package main

import (
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/idna"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

type TContent struct {
	Url                   []string `xml:"url"`
	IP                    []string `xml:"ip"`
	Domain                string   `xml:"dns"`
	Id                    string   `xml:"id,attr"`
	IncludeTime           string   `xml:"dateoff"` // sorry :)) GetCurseOnDate() Fraking KGB!!!
	BlockType             string   `xml:"-"`
	BogusDomain, BogusURL bool     `xml:"-"`
}

type TReg struct {
	UpdateTime string
}

type TStat struct {
	Records                 int `json: records`                   // record's count
	URLs                    int `json: urls`                      // not uniq url's count
	URLsUnique              int `json: urls_unique`               // unique url's count
	URLsSpecialChar         int `json: urls_special_chars`        // urls with special chars
	URLsNotUrlencoded       int `json: urls_not_urlencoded`       // not urlencoded urls
	URLsAnchor              int `json: urls_anchor`               // urls with anchor
	URLsSession             int `json: urls_session`              // urls with sessions
	URLsMalformed           int `json: urls_malformed`            // malformed urls
	URLsWithBogusSchema     int `json: ursl_bogus_schema`         // bogus schema (not http(s)://)
	DomainsUnique           int `json: domains_unique`            // unique domains
	DomainsNotACEIDNA       int `json: domains_not_ace_idna`      // not ACE-encoded IDNA domains (not uniq)
	DomainsUniqueIDNA       int `json: domains_unique_idna`       // unique IDNA domains
	DomainsDifferentIPSet   int `json: domains_different_ipset`   // domains with different IP sets
	DomainsNotUrlencodedURL int `json: domains_noturlencoded_url` // domains with not urlencoded url
	DomainsBogus            int `json: domains_bogus`             // bogus domains
	BlocksUnknown           int `json: blocks_unknown`            // unknown blocktypr count
	BlocksDefault           int `json: blocks_default`            // blocktype=defailt count
	BlocksHTTPS             int `json: blocks_https`              // blocktype=https count
	BlocksDomain            int `json: blocks_domain`             // blocktype=domain count
	BlocksIP                int `json: blocks_ip`                 // blocktype=ip count
	NotIPUniqIP4            int `json: notip_uniq_ip4`            // unique ipv4  count (not blocktype=ip)
	NotIPIP4Count           int `json: notip_count_ip4`           // ip4 count with subnets (not blocktype=ip)
	IPUniqIP4               int `json: ip_uniq_ip4`               // unique ipv4  count (blocktype=ip)
	IPCountIP4              int `json: ip_count_ip4`              // ip6 count with subnets (blocktype=ip)
	RecordsWithoutIP        int `json: records_without_ip`        // records without any ip or subnet
	Redundancy              int `json: redundancy`                // redundancy
}

type Tdtype struct {
	Url, Domain int
}

type TIPSet map[[32]byte]bool

func main() {
	Reg := TReg{}
	Stat := TStat{}
	U_IP := make(map[string]bool)
	U_SIP := make(map[string]bool)
	U_Domain := make(map[string]bool)
	U_IDNADomain := make(map[string]bool)
	Type_domain := make(map[string]*Tdtype)
	DomainIPSet := make(map[string]TIPSet)
	vygruzka, err := os.Open("dump.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer vygruzka.Close()
	decoder := xml.NewDecoder(vygruzka)
	decoder.CharsetReader = charset.NewReaderLabel
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	for {
		t, err := decoder.Token()
		if t == nil {
			if err != io.EOF {
				fmt.Printf("Error: %s\n", err.Error())
			}
			break
		}
		switch _e := t.(type) {
		case xml.StartElement:
			_name := _e.Name.Local
			switch _name {
			case "resources":
				for _, _a := range _e.Attr {
					if _a.Name.Local == "date" {
						Reg.UpdateTime = _a.Value
					}
				}
			case "resource":
				Stat.Records++
				var v TContent
				var _domain string
				err := decoder.DecodeElement(&v, &_e)
				if err != nil {
					fmt.Printf("Decode Error: %s\n", err.Error())
				}
				// calc blocktype
				if len(v.IP) > 0 && v.IP[0] != "-" {
					v.BlockType = "ip"
				}
				if v.Domain != "-" {
					v.BlockType = "domain"
				}
				if len(v.Url) > 0 && v.Url[0] != "-" {
					v.BlockType = "default"
				}
				if v.Domain != "-" {
					v.Domain = strings.ToLower(v.Domain)
					v.Domain = strings.TrimRight(v.Domain, "\r\n")
					v.Domain = strings.TrimSpace(v.Domain)
					domain, err := idna.ToASCII(v.Domain)
					if err != nil {
						fmt.Printf("IDNA parse error: %s\n", err.Error())
						continue
					}
					if domain != v.Domain {
						v.Domain = domain
						Stat.DomainsNotACEIDNA++
						//fmt.Printf("D: %s\n%s\n\n", _d, v.Domain)
					}
					U_Domain[v.Domain] = true
					if strings.Contains(v.Domain, "xn--") {
						U_IDNADomain[v.Domain] = true
					}
					_domain = strings.TrimPrefix(domain, "*.")
					if !re.MatchString(_domain) && !isDomainName(_domain) {
						Stat.DomainsBogus++
						fmt.Printf("Bogus domain: %s\n", v.Domain)
					}
				}
				for i, u := range v.Url {
					if i == 0 && u == "-" {
						break
					}
					Stat.URLs++
					u = strings.TrimRight(u, "\r\n")
					u = strings.TrimSpace(u)
					var _u string = u
					urlurl, err := url.Parse(u)
					if err != nil {
						Stat.URLsMalformed++
						fmt.Printf("URL parse error: ID: %s Domain: %s URL: %s\n", v.Id, v.Domain, u)
						continue
					}
					urlDomain := strings.ToLower(urlurl.Host)
					if strings.HasPrefix(u, "https://"+urlurl.Host) {
						u = strings.Replace(u, "https://"+urlurl.Host, "https://"+urlDomain, 1)
					} else if strings.HasPrefix(u, "http://"+urlurl.Host) {
						u = strings.Replace(u, "http://"+urlurl.Host, "http://"+urlDomain, 1)
					}
					urlurl.Host, err = idna.ToASCII(urlDomain)
					if err != nil {
						fmt.Printf("IDNA parse error: %s\n", err.Error())
						continue
					}
					newurl := urlurl.String()
					if _u != newurl {
						v.Url[i] = newurl
						if u != newurl {
							Stat.URLsNotUrlencoded++
							v.BogusURL = true
							//fmt.Printf("Ub: %s\n%s\n%s\n\n", _u, u, newurl)
						}
					}
					if strings.Contains(v.Url[i], "%") {
						Stat.URLsSpecialChar++
					}
					if urlurl.RawQuery != "" {
						v := urlurl.Query()
						if v.Get("sid") != "" || v.Get("session") != "" || v.Get("session_id") != "" || v.Get("sess") != "" {
							Stat.URLsSession++
							fmt.Printf("Us: %s\n", urlurl.String())
						}
					}
					if urlurl.Fragment != "" {
						fmt.Printf("Uf: %s\n", urlurl.String())
						Stat.URLsAnchor++
					}
					if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
						fmt.Printf("Bigus schema: ID: %s Domain: %s URL: %s\n", v.Id, v.Domain, u)
					} else {
						_i := strings.LastIndex(u, "https://")
						_j := strings.LastIndex(u, "http://")
						if _i > 0 {
							if u[_i-1] == ' ' {
								fmt.Printf("Double schema: ID: %s Domain: %s URL: %s\n", v.Id, v.Domain, u)
							}
						}
						if _j > 0 {
							if u[_j-1] == ' ' {
								fmt.Printf("Double schema: ID: %s Domain: %s URL: %s\n", v.Id, v.Domain, u)
							}
						}
					}
					if urlurl.Scheme == "https" {
						Stat.BlocksHTTPS++
					}
					if _domain != "" {
						if _domain != urlDomain {
							fmt.Printf("Different domains: ID: %s Domain: %s URL: %s\n", v.Id, v.Domain, u)
						}
					} else {
						_domain = urlDomain
					}
				}
				_ips := make([]string, 1)
				for i, u := range v.IP {
					if i == 0 && u == "-" {
						break
					}
					U_IP[u] = true
					_ips = append(_ips, u)
					if v.BlockType == "ip" {
						U_SIP[u] = true
					}
				}
				sort.Strings(_ips)
				if v.Domain != "-" {
					if _, ok := DomainIPSet[v.Domain]; !ok {
						DomainIPSet[v.Domain] = make(TIPSet)
					}
					DomainIPSet[v.Domain][sha256.Sum256([]byte(strings.Join(_ips, "")))] = true
				}
				if len(v.IP) == 1 && v.IP[0] == "-" {
					Stat.RecordsWithoutIP++
					// fmt.Printf("Content without IP: %#v\n", v)
				}
				if v.BogusURL {
					Stat.DomainsNotUrlencodedURL++
				}
				if v.BlockType == "domain" {
					Stat.BlocksDomain++
					if _v, ok := Type_domain[_domain]; ok {
						_v.Domain++
					} else {
						Type_domain[_domain] = &Tdtype{Domain: 1}
					}
				} else if v.BlockType == "ip" {
					Stat.BlocksIP++
				} else if v.BlockType == "default" {
					Stat.BlocksDefault++
					if _v, ok := Type_domain[_domain]; ok {
						_v.Url++
					} else {
						Type_domain[_domain] = &Tdtype{Url: 1}
					}
				} else {
					Stat.BlocksUnknown++
				}
			}
		default:
			//fmt.Printf("%v\n", _e)
		}
	}
	Stat.NotIPUniqIP4 = len(U_IP)
	Stat.DomainsUnique = len(U_Domain)
	Stat.DomainsUniqueIDNA = len(U_IDNADomain)
	Stat.IPUniqIP4 = len(U_SIP)
	for domain, ipset := range DomainIPSet {
		if len(ipset) > 1 {
			Stat.DomainsDifferentIPSet++
			domain += ""
			//fmt.Printf("*** different IP sets for same domain: %s\n", domain)
		}
	}
	for _, t := range Type_domain {
		if t.Domain > 0 {
			Stat.Redundancy += t.Domain + t.Url - 1
		}
	}
	fmt.Printf("\n")
	fmt.Printf("Register Date: %s\n", Reg.UpdateTime)
	fmt.Printf("\n")
	fmt.Printf("All register records: %d\n", Stat.Records)
	fmt.Printf("\n")
	fmt.Printf("Redundancy: %d\n", Stat.Redundancy)
	fmt.Printf("\n")
	fmt.Printf("Unique domains: %d\n", Stat.DomainsUnique)
	fmt.Printf("Unique IDNA domains: %d (%.1f%%)\n", Stat.DomainsUniqueIDNA, float32(Stat.DomainsUniqueIDNA)/float32(Stat.DomainsUnique)*100.0)
	fmt.Printf("Not ACE-encoded IDNA domain strings: %d\n", Stat.DomainsNotACEIDNA)
	fmt.Printf("Number of domains with different IP sets for same domain: %d\n", Stat.DomainsDifferentIPSet)
	fmt.Printf("Number of bogus domains: %d\n", Stat.DomainsBogus)
	fmt.Printf("\n")
	fmt.Printf("Number of URLs: %d\n", Stat.URLs)
	fmt.Printf("Number of URLs with special chars: %d (%.1f%%)\n", Stat.URLsSpecialChar, float32(Stat.URLsSpecialChar)/float32(Stat.URLs)*100.0)
	fmt.Printf("Number of not urlencoded URLs: %d (%.1f%%) in %d domains\n", Stat.URLsNotUrlencoded, float32(Stat.URLsNotUrlencoded)/float32(Stat.URLs)*100.0, Stat.DomainsNotUrlencodedURL)
	fmt.Printf("Number of URLs with fragment (# anchor): %d\n", Stat.URLsAnchor)
	fmt.Printf("Number of URLs with session in query (sid, session, session_id value(s)): %d\n", Stat.URLsSession)
	fmt.Printf("Number of malformed URLs: %d\n", Stat.URLsMalformed)
	fmt.Printf("\n")
	fmt.Printf("Number of the default block type records: %d (%.1f%%): https: %d (%.1f%%)\n", Stat.BlocksDefault, float32(Stat.BlocksDefault)/float32(Stat.Records)*100.0, Stat.BlocksHTTPS, float32(Stat.BlocksHTTPS)/float32(Stat.Records)*100.0)
	fmt.Printf("Number of the domain block type records: %d (%.1f%%)\n", Stat.BlocksDomain, float32(Stat.BlocksDomain)/float32(Stat.Records)*100.0)
	fmt.Printf("Number of the IP block type records: %d (%.1f%%)\n", Stat.BlocksIP, float32(Stat.BlocksIP)/float32(Stat.Records)*100.0)
	fmt.Printf("Number of the UNKNOWN block type records: %d (%.1f%%)\n", Stat.BlocksUnknown, float32(Stat.BlocksUnknown)/float32(Stat.Records)*100.0)
	fmt.Printf("\n")
	fmt.Printf("Number of IPs: %d\n", Stat.NotIPUniqIP4)
	fmt.Printf("Records without IPs: %d\n", Stat.RecordsWithoutIP)
	fmt.Printf("\n")
	fmt.Printf("Number of strict blocked IPs: %d\n", Stat.IPUniqIP4)
}
