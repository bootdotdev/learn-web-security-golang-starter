package main

import (
	"encoding/json"
	"os"
	"path"
	"strings"
)

type result struct {
	MultiStageBuild             bool `json:"multiStageBuild"`
	StaticBinariesBuilt         bool `json:"staticBinariesBuilt"`
	NarrowRuntimeImage          bool `json:"narrowRuntimeImage"`
	UnprivilegedRuntime         bool `json:"unprivilegedRuntime"`
	SensitiveFilesExcluded      bool `json:"sensitiveFilesExcluded"`
	GeneratedDataExcluded       bool `json:"generatedDataExcluded"`
	RequiredBuildInputsIncluded bool `json:"requiredBuildInputsIncluded"`
}

func main() {
	dockerfileBytes, _ := os.ReadFile("Dockerfile")
	dockerfile := normalizedDockerfile(string(dockerfileBytes))
	buildStage, runtimeStage, stagesFound := dockerfileStages(dockerfile)
	dockerignoreBytes, _ := os.ReadFile(".dockerignore")
	patterns := ignorePatterns(string(dockerignoreBytes))

	writeResult(result{
		MultiStageBuild:             stagesFound,
		StaticBinariesBuilt:         stagesFound && validBuildStage(buildStage),
		NarrowRuntimeImage:          stagesFound && validRuntimeStage(runtimeStage),
		UnprivilegedRuntime:         stagesFound && unprivilegedRuntime(runtimeStage),
		SensitiveFilesExcluded:      allIgnored(patterns, []string{".env", ".env.local", ".git/config", "tmp/cache", "bearly-secure.log"}),
		GeneratedDataExcluded:       allIgnored(patterns, []string{"data/bearly-secure.sqlite", "data/bearly-secure.sqlite-wal", "data/bulk-tax-documents/import.zip", "data/uploads/untrusted.pdf"}),
		RequiredBuildInputsIncluded: allIncluded(patterns, []string{"go.mod", "go.sum", "cmd/server/main.go", "internal/config/config.go", "web/public/styles.css", "attacker-lab/index.html", "data/uploads/mystery-shack-tax-exemption.pdf"}),
	})
}

func normalizedDockerfile(contents string) string {
	instructions := []string{}
	logicalLine := ""
	for physicalLine := range strings.SplitSeq(contents, "\n") {
		trimmedLine := strings.TrimSpace(physicalLine)
		if logicalLine == "" && (trimmedLine == "" || strings.HasPrefix(trimmedLine, "#")) {
			continue
		}
		logicalLine += " " + trimmedLine
		if before, ok := strings.CutSuffix(logicalLine, "\\"); ok {
			logicalLine = strings.TrimSpace(before)
			continue
		}

		instructions = append(instructions, strings.ToLower(strings.TrimSpace(logicalLine)))
		logicalLine = ""
	}
	return strings.Join(instructions, "\n")
}

func dockerfileStages(dockerfile string) (string, string, bool) {
	buildMarker := "from golang:1.27.0-alpine as build"
	runtimeMarker := "from alpine:3.22"
	buildStart := strings.Index(dockerfile, buildMarker)
	runtimeStart := strings.Index(dockerfile, runtimeMarker)
	if buildStart < 0 || runtimeStart <= buildStart || strings.Count(dockerfile, "from ") != 2 {
		return "", "", false
	}
	return dockerfile[buildStart:runtimeStart], dockerfile[runtimeStart:], true
}

func validBuildStage(buildStage string) bool {
	return stringsInOrder(buildStage, "workdir /src", "copy go.mod go.sum ./", "run go mod download", "copy . .", "cgo_enabled=0 go build") &&
		containsAll(buildStage, "-o /out/bearly-secure", "./cmd/server", "-o /out/bearly-attacker-lab", "./cmd/attackerlab")
}

func validRuntimeStage(runtimeStage string) bool {
	return containsAll(runtimeStage,
		"apk add --no-cache ca-certificates",
		"workdir /app",
		"copy --from=build",
		"/out/bearly-secure",
		"/out/bearly-attacker-lab",
		"attacker-lab ./attacker-lab",
		"web ./web",
		`cmd ["./bearly-secure"]`,
	) && copiesRuntimeFile(runtimeStage, "data/uploads/mystery-shack-tax-exemption.pdf") && !strings.Contains(runtimeStage, "copy . .")
}

func copiesRuntimeFile(runtimeStage, filename string) bool {
	workdir := "/"
	for line := range strings.SplitSeq(runtimeStage, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "workdir" {
			if path.IsAbs(fields[1]) {
				workdir = path.Clean(fields[1])
			} else {
				workdir = path.Join(workdir, fields[1])
			}
		}
		if len(fields) < 3 || fields[0] != "copy" {
			continue
		}
		args := fields[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			args = args[1:]
		}
		if len(args) != 2 || path.Clean(args[0]) != filename {
			continue
		}
		destination := args[1]
		if !path.IsAbs(destination) {
			destination = path.Join(workdir, destination)
		}
		if strings.HasSuffix(args[1], "/") {
			destination = path.Join(destination, path.Base(filename))
		}
		if path.Clean(destination) == path.Join("/app", filename) {
			return true
		}
	}
	return false
}

func unprivilegedRuntime(runtimeStage string) bool {
	return containsAll(runtimeStage, "adduser -s -g bearly bearly", "chown bearly:bearly ./data") &&
		stringsInOrder(runtimeStage, "user bearly", `cmd ["./bearly-secure"]`)
}

func containsAll(contents string, values ...string) bool {
	for _, value := range values {
		if !strings.Contains(contents, value) {
			return false
		}
	}
	return true
}

func stringsInOrder(contents string, values ...string) bool {
	position := 0
	for _, value := range values {
		index := strings.Index(contents[position:], value)
		if index < 0 {
			return false
		}
		position += index + len(value)
	}
	return true
}

func ignorePatterns(contents string) []string {
	patterns := []string{}
	for line := range strings.SplitSeq(contents, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns
}

func ignored(patterns []string, filename string) bool {
	ignored := false
	for _, patternValue := range patterns {
		negated := strings.HasPrefix(patternValue, "!")
		patternValue = strings.TrimPrefix(patternValue, "!")
		matched := false
		if before, ok := strings.CutSuffix(patternValue, "/"); ok {
			directory := before
			matched = filename == directory || strings.HasPrefix(filename, directory+"/")
		} else if strings.Contains(patternValue, "/") {
			matched, _ = path.Match(patternValue, filename)
		} else {
			matched, _ = path.Match(patternValue, path.Base(filename))
		}
		if matched {
			ignored = !negated
		}
	}
	return ignored
}

func allIgnored(patterns, filenames []string) bool {
	for _, filename := range filenames {
		if !ignored(patterns, filename) {
			return false
		}
	}
	return true
}

func allIncluded(patterns, filenames []string) bool {
	for _, filename := range filenames {
		if ignored(patterns, filename) {
			return false
		}
	}
	return true
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
