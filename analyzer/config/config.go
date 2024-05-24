package config

import (
	"golang.org/x/xerrors"
	"regexp"
	"sort"
	"strings"
	"xcosx/analyzer"
	"xcosx/analyzer/config/dockerfile"
	"xcosx/analyzer/config/terraform"
	"xcosx/analyzer/config/yaml"
	"xcosx/analyzer/weakpass/mysql"
	"xcosx/analyzer/weakpass/redis"
	"xcosx/analyzer/weakpass/ssh"
	"xcosx/analyzer/weakpass/tomcat"
	"xcosx/types"
)

const separator = ":"

type ScannerOption struct {
	Trace                   bool
	RegoOnly                bool
	Namespaces              []string
	FilePatterns            []string
	PolicyPaths             []string
	DataPaths               []string
	DisableEmbeddedPolicies bool
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.FilePatterns)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

func RegisterConfigAnalyzers(filePatterns []string) error {
	var dockerRegexp, yamlRegexp *regexp.Regexp
	for _, p := range filePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return xerrors.Errorf("invalid file pattern (%s)", p)
		}
		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		switch fileType {
		case types.Dockerfile:
			dockerRegexp = r
		//case types.JSON:
		//	jsonRegexp = r
		case types.YAML:
			yamlRegexp = r
		default:
			return xerrors.Errorf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	analyzer.RegisterAnalyzer(dockerfile.NewConfigAnalyzer(dockerRegexp))
	analyzer.RegisterAnalyzer(terraform.NewConfigAnalyzer())
	//analyzer.RegisterAnalyzer(json.NewConfigAnalyzer(jsonRegexp))
	analyzer.RegisterAnalyzer(yaml.NewConfigAnalyzer(yamlRegexp))
	analyzer.RegisterAnalyzer(ssh.NEWSSHWeakPassAnalyzer())
	analyzer.RegisterAnalyzer(redis.NEWRedisWeakPassAnalyzer())
	analyzer.RegisterAnalyzer(tomcat.NEWTomcatWeakPassAnalyzer())
	analyzer.RegisterAnalyzer(mysql.NEWMysqlWeakPassAnalyzer())

	return nil
}
