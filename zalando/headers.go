package zalando

import (
	"zalando-solutions/utils"

	http "github.com/bogdanfinn/fhttp"
)

var headersAuthenticate = http.Header{
	"upgrade-insecure-requests": {"1"},
	"user-agent":                {utils.UserAgent},
	"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
	"sec-fetch-site":            {"none"},
	"sec-fetch-mode":            {"navigate"},
	"sec-fetch-user":            {"?1"},
	"sec-fetch-dest":            {"document"},
	"sec-ch-ua":                 {utils.SecChUa},
	"sec-ch-ua-mobile":          {"?0"},
	"sec-ch-ua-platform":        {`"Windows"`},
	"accept-encoding":           {"gzip, deflate, br, zstd"},
	"accept-language":           {utils.AcceptLanguage},
	"priority":                  {"u=0, i"},
	http.HeaderOrderKey: {
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	},
	http.PHeaderOrderKey: {
		":method",
		":authority",
		":scheme",
		":path",
	},
}

var headersAuthorize = http.Header{
	"upgrade-insecure-requests": {"1"},
	"user-agent":                {utils.UserAgent},
	"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
	"sec-ch-ua":                 {utils.SecChUa},
	"sec-ch-ua-mobile":          {"?0"},
	"sec-ch-ua-platform":        {`"Windows"`},
	"sec-fetch-site":            {"none"},
	"sec-fetch-mode":            {"navigate"},
	"sec-fetch-user":            {"?1"},
	"sec-fetch-dest":            {"document"},
	"accept-encoding": {"gzip, deflate, br, zstd"},
	"accept-language": {utils.AcceptLanguage},
	"priority":        {"u=0, i"},
	http.HeaderOrderKey: {
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	},
	http.PHeaderOrderKey: {
		":method",
		":authority",
		":scheme",
		":path",
	},
}
