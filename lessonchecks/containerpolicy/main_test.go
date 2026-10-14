package main

import "testing"

func TestValidRuntimeStageCopyDestination(t *testing.T) {
	const prefix = `FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/bearly-secure ./bearly-secure
COPY --from=build /out/bearly-attacker-lab ./bearly-attacker-lab
COPY attacker-lab ./attacker-lab
COPY web ./web
`
	const suffix = "\nCMD [\"./bearly-secure\"]\n"
	const pdf = "data/uploads/mystery-shack-tax-exemption.pdf"
	tests := []struct {
		name string
		copy string
		want bool
	}{
		{"dot relative", "COPY " + pdf + " ./" + pdf, true},
		{"relative", "COPY " + pdf + " " + pdf, true},
		{"ownership flag", "COPY --chown=bearly:bearly " + pdf + " " + pdf, true},
		{"absolute", "COPY " + pdf + " /app/" + pdf, true},
		{"dot relative source", "COPY ./" + pdf + " " + pdf, true},
		{"directory destination", "COPY " + pdf + " ./data/uploads/", true},
		{"wrong absolute directory", "COPY " + pdf + " /" + pdf, false},
		{"wrong relative directory", "COPY " + pdf + " uploads/mystery-shack-tax-exemption.pdf", false},
		{"wrong filename", "COPY " + pdf + " ./" + pdf + ".bak", false},
		{"wrong source", "COPY other.pdf ./" + pdf, false},
		{"wrong workdir", "WORKDIR /other\nCOPY " + pdf + " " + pdf, false},
		{"missing copy", "", false},
		{"comment only", "# COPY " + pdf + " ./" + pdf, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validRuntimeStage(normalizedDockerfile(prefix + tt.copy + suffix))
			if got != tt.want {
				t.Fatalf("validRuntimeStage() = %v, want %v", got, tt.want)
			}
		})
	}
}
