package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/config"
)

type policyResult struct {
	SiteAddressConfigured    bool `json:"siteAddressConfigured"`
	AutomaticHTTPSEnabled    bool `json:"automaticHttpsEnabled"`
	ReverseProxyConfigured   bool `json:"reverseProxyConfigured"`
	HSTSConfigured           bool `json:"hstsConfigured"`
	EnvironmentDocumented    bool `json:"environmentDocumented"`
	ConfiguredHopCountExact  bool `json:"configuredHopCountExact"`
	NegativeHopCountRejected bool `json:"negativeHopCountRejected"`
	ServerWiringConfigured   bool `json:"serverWiringConfigured"`
}

func main() {
	caddyBytes, _ := os.ReadFile("Caddyfile")
	caddyContents := stripCaddyComments(string(caddyBytes))
	configuredSiteBlock := caddySiteBlock(caddyContents)
	siteAddressConfigured := configuredSiteBlock != ""
	automaticHTTPSDisabled := regexp.MustCompile(`(?i)\bauto_https[ \t]+(off|disable_redirects)\b`).MatchString(caddyContents)
	reverseProxyConfigured := regexp.MustCompile(`(?m)^[ \t]*reverse_proxy[ \t]+127\.0\.0\.1:3030[ \t]*$`).MatchString(configuredSiteBlock)
	hstsConfigured := regexp.MustCompile(`(?mi)^[ \t]*header[ \t]+Strict-Transport-Security[ \t]+"max-age=31536000; includeSubDomains"[ \t]*$`).MatchString(configuredSiteBlock)

	configuredHopCountExact, negativeHopCountRejected := configPolicy()
	environmentBytes, _ := os.ReadFile(".env.example")

	output := policyResult{
		SiteAddressConfigured:    siteAddressConfigured,
		AutomaticHTTPSEnabled:    siteAddressConfigured && !automaticHTTPSDisabled,
		ReverseProxyConfigured:   reverseProxyConfigured,
		HSTSConfigured:           hstsConfigured,
		EnvironmentDocumented:    hasExactLine(string(environmentBytes), "TRUST_PROXY_HOPS=0"),
		ConfiguredHopCountExact:  configuredHopCountExact,
		NegativeHopCountRejected: negativeHopCountRejected,
		ServerWiringConfigured:   serverWiringConfigured(),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}

func stripCaddyComments(contents string) string {
	lines := strings.Split(contents, "\n")
	for lineIndex, line := range lines {
		if uncommented, _, found := strings.Cut(line, "#"); found {
			lines[lineIndex] = uncommented
		}
	}
	return strings.Join(lines, "\n")
}

func caddySiteBlock(contents string) string {
	sitePattern := regexp.MustCompile(`(?ms)(^|\n)[ \t]*bearly-secure\.example[ \t]*\{(.*?)^[ \t]*\}`)
	matches := sitePattern.FindStringSubmatch(contents)
	if len(matches) < 3 {
		return ""
	}
	return matches[2]
}

func configPolicy() (bool, bool) {
	environment := map[string]string{
		"PAWPAL_API_KEY":       "pawpal-test-key",
		"DOWNLOAD_SIGNING_KEY": strings.Repeat("ab", 32),
		"TRUST_PROXY_HOPS":     "2",
	}
	parsedConfig, err := config.Parse(environment, ".")
	if err != nil {
		return false, false
	}
	field := reflect.ValueOf(parsedConfig).FieldByName("TrustedProxyHops")
	configuredHopCountExact := field.IsValid() && field.Kind() == reflect.Int && field.Int() == 2
	environment["TRUST_PROXY_HOPS"] = "-1"
	_, err = config.Parse(environment, ".")
	return configuredHopCountExact, err != nil
}

func serverWiringConfigured() bool {
	parsed, err := parser.ParseFile(token.NewFileSet(), "cmd/server/main.go", nil, 0)
	if err != nil {
		return false
	}
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		keyValue, ok := node.(*ast.KeyValueExpr)
		if !ok || identifierName(keyValue.Key) != "TrustedProxyHops" {
			return true
		}
		selector, ok := keyValue.Value.(*ast.SelectorExpr)
		found = ok && identifierName(selector.X) == "appConfig" && selector.Sel.Name == "TrustedProxyHops"
		return !found
	})
	return found
}

func identifierName(expression ast.Expr) string {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name
}

func hasExactLine(contents, expected string) bool {
	for line := range strings.SplitSeq(contents, "\n") {
		if line == expected {
			return true
		}
	}
	return false
}
