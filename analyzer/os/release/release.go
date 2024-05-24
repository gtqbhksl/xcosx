package release

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"xcosx/analyzer"
	aos "xcosx/analyzer/os"
	"xcosx/types"
)

func init() {
	analyzer.RegisterAnalyzer(&osReleaseAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"etc/os-release",
	"usr/lib/os-release",
	"os-release",
}

type osReleaseAnalyzer struct{}

func (a osReleaseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var id, versionID string
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()

		ss := strings.SplitN(line, "=", 2)
		if len(ss) != 2 {
			continue
		}
		key, value := strings.TrimSpace(ss[0]), strings.TrimSpace(ss[1])

		switch key {
		case "ID":
			id = strings.Trim(value, `"'`)
			//fmt.Printf("ID: %s\n", id)
		case "VERSION_ID":
			versionID = strings.Trim(value, `"'`)
			//fmt.Printf("VERSION_ID: %s\n", versionID)
		default:
			continue
		}

		var family string
		family = "none"
		switch id {
		case "openEuler":
			family = aos.OpenEuler
		case "alinos":
			family = aos.Alinos
		case "kali":
			family = "kali"
		}
		if versionID == "8.9" {
			versionID = "8"
		}
		if family != "" && versionID != "" {
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: family, Name: versionID},
			}, nil
		}
	}

	return nil, nil
}

func (a osReleaseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a osReleaseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeOSRelease
}

func (a osReleaseAnalyzer) Version() int {
	return version
}
