package pac

import (
	"net/url"
	"time"
)

type ResultType int

const (
	ResultUnknown ResultType = iota
	ResultDirect
	ResultProxy
)

type ProxyInfo struct {
	Scheme string
	Host   string
}

type PacResult struct {
	Type    ResultType
	Proxies []ProxyInfo
}

type dnsCacheEntry struct {
	ip     string
	expiry time.Time
}

func (p ProxyInfo) URL() (*url.URL, error) {
	urlString := p.Scheme + "://" + p.Host
	return url.Parse(urlString)
}
