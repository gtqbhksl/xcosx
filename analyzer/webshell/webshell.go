package webshell

import (
	"context"
	"golang.org/x/xerrors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"xcosx/analyzer"
	"xcosx/types"
	"xcosx/webshell"
)

const version = 1

var (
	requiredExts = []string{".php", ".asp", "jsp", "aspx", "jspx", "js", "jspx", "php3", "php4", "php5"}
	//excludedFiles = []string{types.NpmPkgLock, types.NuGetPkgsLock, types.NuGetPkgsConfig}
)

type ScannerOption struct {
	ConfigPath string
}

type WebshellAnalyzer struct {
	filePattern *regexp.Regexp
	scanner     webshell.Scanner
	configPath  string
}

func RegisterWebshellAnalyzer(opt ScannerOption) error {
	a, err := newWebshellAnalyzer(opt.ConfigPath)
	if err != nil {
		return xerrors.Errorf("webshell scanner init error: %w", err)
	}
	analyzer.RegisterAnalyzer(a)
	return nil
}

func newWebshellAnalyzer(configPath string) (WebshellAnalyzer, error) {
	s, err := webshell.NewScanner(configPath)
	if err != nil {
		return WebshellAnalyzer{}, xerrors.Errorf("webshell scanner error: %w", err)
	}
	return WebshellAnalyzer{
		scanner:    s,
		configPath: configPath,
	}, nil
}

func (a WebshellAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}
	result := a.scanner.Scan(webshell.ScanArgs{
		FilePath: input.FilePath,
		Content:  b,
	})

	return &analyzer.AnalysisResult{
		WebshellResult: []types.WebshellResult{{
			FilePath: result.FilePath,
			Score:    result.Score,
			Source:   result.Source,
		},
		},
	}, nil
}

func (a WebshellAnalyzer) Required(filePath string, _ os.FileInfo) bool {

	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (WebshellAnalyzer) Type() analyzer.Type {
	return analyzer.TypeWebshell
}

func (WebshellAnalyzer) Version() int {
	return version
}
