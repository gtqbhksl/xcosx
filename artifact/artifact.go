package artifact

import (
	"context"
	"sort"
	"xcosx/analyzer/webshell"

	"xcosx/analyzer"
	misconf "xcosx/analyzer/config"
	"xcosx/analyzer/secret"
	"xcosx/types"
)

type Option struct {
	AnalyzerGroup     analyzer.Group // It is empty in OSS
	DisabledAnalyzers []analyzer.Type
	DisabledHandlers  []types.HandlerType
	SkipFiles         []string
	SkipDirs          []string
	NoProgress        bool
	Offline           bool
	InsecureSkipTLS   bool

	MisconfScannerOption  misconf.ScannerOption
	SecretScannerOption   secret.ScannerOption
	WebshellScannerOption webshell.ScannerOption
}

func (o *Option) Sort() {
	sort.Slice(o.DisabledAnalyzers, func(i, j int) bool {
		return o.DisabledAnalyzers[i] < o.DisabledAnalyzers[j]
	})
	sort.Strings(o.SkipFiles)
	sort.Strings(o.SkipDirs)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
	Clean(reference types.ArtifactReference) error
}
