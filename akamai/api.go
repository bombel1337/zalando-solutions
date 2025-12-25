package akamai

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
)

var (
	authHrefExpr = regexp.MustCompile(`(?is)"href"\s*:\s*"(https://accounts\.zalando\.com/authenticate\?[^"]+)"`)

	sensorScriptPathExpr = regexp.MustCompile(`<script type="text/javascript"\s+(?:nonce=".*")?\s+src="((?i)[a-z\d/\-_]+)"></script>`)
	sbsdScriptPathExpr   = regexp.MustCompile(`(?is)\bsrc\s*=\s*["']([^"'\?]+)\?[^"']*?\bv=([^"'&]+)`)

	rePixelBazaExpr  = regexp.MustCompile(`bazadebezolkohpepadr\s*=\s*"([^"]+)"`)
	reScriptPathExpr = regexp.MustCompile(`(?is)<script[^>]*\bsrc\s*=\s*"([^"]*/akam/[^"]+)"[^>]*>`)

	pixelScriptVarExpr         = regexp.MustCompile(`g=_\[(\d+)]`)
	pixelScriptStringArrayExpr = regexp.MustCompile(`var _=\[(.+)];`)
	pixelScriptStringsExpr     = regexp.MustCompile(`("[^",]*")`)
)

func CreateAkamaiSession(apiKey string) *hyper.Session {
	return hyper.NewSession(apiKey)
}

func ParseScriptPathSensor(src []byte) (string, error) {
	matches := sensorScriptPathExpr.FindSubmatch(src)
	if len(matches) < 2 {
		return "", fmt.Errorf("script path not found")
	}

	blockLink := string(matches[1])
	blockLink = strings.ReplaceAll(blockLink, "&amp;", "&")

	return blockLink, nil
}
func ParsePixelScriptVar(reader io.Reader) (string, error) {
	src, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("script var not found: %s", err)
	}

	index := pixelScriptVarExpr.FindSubmatch(src)
	if len(index) < 2 {
		return "", fmt.Errorf("script var not found: %s", err)
	}
	stringIndex, err := strconv.Atoi(string(index[1]))
	if err != nil {
		return "", fmt.Errorf("script var not found: %s", err)
	}

	arrayDeclaration := pixelScriptStringArrayExpr.FindSubmatch(src)
	if len(arrayDeclaration) < 2 {
		return "", fmt.Errorf("script var not found: %s", err)
	}

	rawStrings := pixelScriptStringsExpr.FindAllSubmatch(arrayDeclaration[1], -1)
	if stringIndex >= len(rawStrings) {
		return "", fmt.Errorf("script var not found: %s", err)
	}

	if len(rawStrings[stringIndex]) < 2 {
		return "", fmt.Errorf("script var not found: %s", err)
	}

	if v, err := strconv.Unquote(string(rawStrings[stringIndex][1])); err == nil {
		return v, nil
	} else {
		return "", fmt.Errorf("script var not found: %s", err)
	}
}

func ParsePixel(src []byte) (string, string, error) {
	matches := reScriptPathExpr.FindSubmatch(src)
	if len(matches) < 2 {
		return "", "", fmt.Errorf("script src not found")
	}

	link := string(matches[1])
	for _, v := range matches {
		fmt.Println(string(v))
	}
	matches = rePixelBazaExpr.FindSubmatch(src)
	if len(matches) < 2 {
		return "", "", fmt.Errorf("bazadebezolkohpepadr not found")
	}
	baza := string(matches[1])

	return baza, link, nil
}
func ParseScriptPathSbsd(src []byte) (path string, v string, err error) {

	m := sbsdScriptPathExpr.FindSubmatch(src)
	if len(m) < 3 {
		return "", "", fmt.Errorf("script path not found")
	}

	path = strings.ReplaceAll(string(m[1]), "&amp;", "&")
	v = string(m[2])
	return path, v, nil
}

func IsCookieValid(cookie string, requestCount int) bool {
	parts := strings.Split(cookie, "~")
	if len(parts) < 2 {
		return false
	}

	requestThreshold, err := strconv.Atoi(parts[1])
	if err != nil {
		requestThreshold = -1
	}

	return requestThreshold != -1 && requestCount >= requestThreshold
}

func IsCookieInvalidated(cookie string) bool {
	parts := strings.Split(cookie, "~")
	if len(parts) < 4 {
		return false
	}

	signal, err := strconv.Atoi(parts[3])
	if err != nil {
		signal = -1
	}

	return signal > -1
}
