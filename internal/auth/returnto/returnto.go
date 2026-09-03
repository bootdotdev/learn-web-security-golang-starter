package returnto

var allowedPaths = map[string]struct{}{
	"/":                              {},
	"/account":                       {},
	"/account/assistant":             {},
	"/account/passkey":               {},
	"/account/totp":                  {},
	"/admin/image-preview":           {},
	"/support/tax-exemptions/import": {},
}

func Safe(value string) string {
	if _, allowed := allowedPaths[value]; allowed {
		return value
	}
	return "/"
}
