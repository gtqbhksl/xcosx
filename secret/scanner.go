package secret

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"xcosx/log"
	"xcosx/types"
)

//TODO:https://github.com/chaitin/veinmind-tools/blob/master/plugins/go/veinmind-sensitive/embed/rules.toml
//待补充敏感信息检测规则

var lineSep = []byte{'\n'}

type Scanner struct {
	*Global
}

type Config struct {
	// Enable only specified built-in rules. If only one ID is specified, all other rules are disabled.
	// All the built-in rules are enabled if this field is not specified. It doesn't affect custom rules.
	EnableBuiltinRuleIDs []string `yaml:"enable-builtin-rules"`

	// Disable rules. It is applied to enabled IDs.
	DisableRuleIDs []string `yaml:"disable-rules"`

	// Disable allow rules.
	DisableAllowRuleIDs []string `yaml:"disable-allow-rules"`

	CustomRules      []Rule       `yaml:"rules"`
	CustomAllowRules AllowRules   `yaml:"allow-rules"`
	ExcludeBlock     ExcludeBlock `yaml:"exclude-block"`
}

type Global struct {
	Rules        []Rule
	AllowRules   AllowRules
	ExcludeBlock ExcludeBlock
}

// Allow checks if the match is allowed
func (g Global) Allow(match string) bool {
	return g.AllowRules.Allow(match)
}

// AllowPath checks if the path is allowed
func (g Global) AllowPath(path string) bool {
	return g.AllowRules.AllowPath(path)
}

// Regexp adds unmarshalling from YAML for regexp.Regexp
type Regexp struct {
	*regexp.Regexp
}

func MustCompile(str string) *Regexp {
	return &Regexp{regexp.MustCompile(str)}
}

// UnmarshalYAML unmarshals YAML into a regexp.Regexp
func (r *Regexp) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	regex, err := regexp.Compile(v)
	if err != nil {
		return xerrors.Errorf("regexp compile error: %w", err)
	}

	r.Regexp = regex
	return nil
}

type Rule struct {
	ID              string                   `yaml:"id"`
	Category        types.SecretRuleCategory `yaml:"category"`
	Title           string                   `yaml:"title"`
	Severity        string                   `yaml:"severity"`
	Regex           *Regexp                  `yaml:"regex"`
	Keywords        []string                 `yaml:"keywords"`
	Path            *Regexp                  `yaml:"path"`
	AllowRules      AllowRules               `yaml:"allow-rules"`
	ExcludeBlock    ExcludeBlock             `yaml:"exclude-block"`
	SecretGroupName string                   `yaml:"secret-group-name"`
}

func (s *Scanner) FindLocations(r Rule, content []byte) []Location {
	if r.Regex == nil {
		return nil
	}

	if r.SecretGroupName != "" {
		return s.FindSubmatchLocations(r, content)
	}

	var locs []Location
	indices := r.Regex.FindAllIndex(content, -1)
	for _, index := range indices {
		loc := Location{
			Start: index[0],
			End:   index[1],
		}

		if s.AllowLocation(r, content, loc) {
			continue
		}

		locs = append(locs, loc)
	}
	return locs
}

func (s *Scanner) FindSubmatchLocations(r Rule, content []byte) []Location {
	var submatchLocations []Location
	matchsIndices := r.Regex.FindAllSubmatchIndex(content, -1)
	for _, matchIndices := range matchsIndices {
		matchLocation := Location{ // first two indexes are always start and end of the whole match
			Start: matchIndices[0],
			End:   matchIndices[1],
		}

		if s.AllowLocation(r, content, matchLocation) {
			continue
		}

		matchSubgroupsLocations := r.getMatchSubgroupsLocations(matchIndices)
		if len(matchSubgroupsLocations) > 0 {
			submatchLocations = append(submatchLocations, matchSubgroupsLocations...)
		}
	}
	return submatchLocations
}

func (s *Scanner) AllowLocation(r Rule, content []byte, loc Location) bool {
	match := string(content[loc.Start:loc.End])
	return s.Allow(match) || r.Allow(match)
}

func (r *Rule) getMatchSubgroupsLocations(matchLocs []int) []Location {
	var locations []Location
	for i, name := range r.Regex.SubexpNames() {
		if name == r.SecretGroupName {
			startLocIndex := 2 * i
			endLocIndex := startLocIndex + 1
			locations = append(locations, Location{Start: matchLocs[startLocIndex], End: matchLocs[endLocIndex]})
		}
	}
	return locations
}

func (r *Rule) MatchPath(path string) bool {
	return r.Path == nil || r.Path.MatchString(path)
}

func (r *Rule) MatchKeywords(content []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}

	for _, kw := range r.Keywords {
		if bytes.Contains(bytes.ToLower(content), []byte(strings.ToLower(kw))) {
			return true
		}
	}

	return false
}

func (r *Rule) AllowPath(path string) bool {
	return r.AllowRules.AllowPath(path)
}

func (r *Rule) Allow(match string) bool {
	return r.AllowRules.Allow(match)
}

type AllowRule struct {
	ID          string  `yaml:"id"`
	Description string  `yaml:"description"`
	Regex       *Regexp `yaml:"regex"`
	Path        *Regexp `yaml:"path"`
}

type AllowRules []AllowRule

func (rules AllowRules) AllowPath(path string) bool {
	for _, rule := range rules {
		if rule.Path != nil && rule.Path.MatchString(path) {
			return true
		}
	}
	return false
}

func (rules AllowRules) Allow(match string) bool {
	for _, rule := range rules {
		if rule.Regex != nil && rule.Regex.MatchString(match) {
			return true
		}
	}
	return false
}

type ExcludeBlock struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
}

type Location struct {
	Start int
	End   int
}

func (l Location) Match(loc Location) bool {
	return l.Start <= loc.Start && loc.End <= l.End
}

type Blocks struct {
	content []byte
	regexes []*Regexp
	locs    []Location
	once    *sync.Once
}

func newBlocks(content []byte, regexes []*Regexp) Blocks {
	return Blocks{
		content: content,
		regexes: regexes,
		once:    new(sync.Once),
	}
}

func (b *Blocks) Match(block Location) bool {
	b.once.Do(b.find)
	for _, loc := range b.locs {
		if loc.Match(block) {
			return true
		}
	}
	return false
}

func (b *Blocks) find() {
	for _, regex := range b.regexes {
		results := regex.FindAllIndex(b.content, -1)
		if len(results) == 0 {
			continue
		}
		for _, r := range results {
			b.locs = append(b.locs, Location{
				Start: r[0],
				End:   r[1],
			})
		}
	}
}

func NewScanner(configPath string) (Scanner, error) {
	//设置默认规则文件
	global := Global{
		Rules:      builtinRules,
		AllowRules: builtinAllowRules,
	}

	// 如果未设置配置文件路径，则使用内置规则。
	if configPath == "" {
		return Scanner{&global}, nil
	}
	// 打开指定的配置文件，如果文件不存在，则输出日志信息并使用内置规则；若打开文件时出现其他错误，则返回错误信息。
	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		// 未检测到敏感文件规则，使用默认规则
		log.Logger.Debugf("未检测到敏感文件规则文件: %s", configPath)
		return Scanner{&global}, nil
	} else if err != nil {
		return Scanner{}, xerrors.Errorf("打开文件错误 %s: %w", configPath, err)
	}
	defer f.Close()

	log.Logger.Infof("正在加载 %s 进行敏感信息扫描...", configPath)

	// 重置全局配置为默认值
	global = Global{}
	// 创建Config变量并尝试从配置文件中解码内容
	var config Config
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return Scanner{}, xerrors.Errorf("secrets config decode error: %w", err)
	}
	// 根据配置启用指定的内置规则
	enabledRules := builtinRules
	if len(config.EnableBuiltinRuleIDs) != 0 {
		// Enable only specified built-in rules
		enabledRules = lo.Filter(builtinRules, func(v Rule, _ int) bool {
			return slices.Contains(config.EnableBuiltinRuleIDs, v.ID)
		})
	}
	// 不管是否启用内置规则，始终启用自定义规则，并将它们添加到已启用规则列表中
	enabledRules = append(enabledRules, config.CustomRules...)

	// Disable specified rules
	global.Rules = lo.Filter(enabledRules, func(v Rule, _ int) bool {
		return !slices.Contains(config.DisableRuleIDs, v.ID)
	})

	// 禁用配置中指定的规则
	allowRules := append(builtinAllowRules, config.CustomAllowRules...)
	global.AllowRules = lo.Filter(allowRules, func(v AllowRule, _ int) bool {
		return !slices.Contains(config.DisableAllowRuleIDs, v.ID)
	})

	global.ExcludeBlock = config.ExcludeBlock

	return Scanner{Global: &global}, nil
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func (s Scanner) Scan(args ScanArgs) types.Secret {
	// 全局允许路径：若传入的文件路径在全局允许的路径列表中，则直接返回一个仅包含该文件路径的types.Secret实例。
	if s.AllowPath(args.FilePath) {
		return types.Secret{
			FilePath: args.FilePath,
		}
	}
	// 初始化一个存储发现结果的切片
	var findings []types.SecretFinding
	// 创建一个全局排除块集合（基于内容和Scanner的ExcludeBlock的正则表达式）
	globalExcludedBlocks := newBlocks(args.Content, s.ExcludeBlock.Regexes)
	// 遍历Scanner的规则集
	for _, rule := range s.Rules {
		//fmt.Println("正在扫描文件:", args.FilePath, rule.Keywords)
		// 检查文件路径是否应由当前规则进行扫描，若不应扫描则跳过此次循环
		if !rule.MatchPath(args.FilePath) {
			continue
		}

		// 检查文件路径是否应在当前规则下被允许，若允许则跳过此次循环
		if rule.AllowPath(args.FilePath) {
			continue
		}

		// 检查文件内容是否包含当前规则的关键词，若不包含则跳过此次循环
		if !rule.MatchKeywords(args.Content) {
			continue
		}

		// 使用当前规则检测文件内容中的敏感信息位置
		locs := s.FindLocations(rule, args.Content)
		if len(locs) == 0 {
			continue
		}
		// 创建一个基于当前规则排除块的正则表达式的本地排除块集合
		localExcludedBlocks := newBlocks(args.Content, rule.ExcludeBlock.Regexes)
		// 遍历找到的所有可能的敏感信息位置
		for _, loc := range locs {
			// Skip the secret if it is within excluded blocks.
			if globalExcludedBlocks.Match(loc) || localExcludedBlocks.Match(loc) {
				continue
			}
			// 将符合要求的敏感信息发现结果添加到findings切片中
			findings = append(findings, toFinding(rule, loc, args.Content))
		}
	}
	// 如果没有发现任何敏感信息，则返回一个空的types.Secret实例
	if len(findings) == 0 {
		return types.Secret{}
	}
	// 否则，返回一个包含文件路径和所有发现的敏感信息的types.Secret实例
	return types.Secret{
		FilePath: args.FilePath,
		Findings: findings,
	}
}

func toFinding(rule Rule, loc Location, content []byte) types.SecretFinding {
	startLine, endLine, matchLine := findLocation(loc.Start, loc.End, content)

	return types.SecretFinding{
		RuleID:    rule.ID,
		Category:  rule.Category,
		Severity:  lo.Ternary(rule.Severity == "", "UNKNOWN", rule.Severity),
		Title:     rule.Title,
		StartLine: startLine,
		EndLine:   endLine,
		Match:     matchLine,
	}
}

func findLocation(start, end int, content []byte) (int, int, string) {
	startLineNum := bytes.Count(content[:start], lineSep) + 1
	endLineNum := startLineNum // TODO: support multi lines

	lineStart := bytes.LastIndex(content[:start], lineSep)
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart += 1
	}

	lineEnd := bytes.Index(content[start:], lineSep)
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}

	match := string(content[start:end])
	matchLine := string(content[lineStart:lineEnd])
	if len(matchLine) > 100 {
		truncatedLineStart := lo.Ternary(start-30 < 0, 0, start-30)
		truncatedLineEnd := lo.Ternary(end+20 > len(content), len(content), end+20)
		matchLine = string(content[truncatedLineStart:truncatedLineEnd])
	}

	// Mask credentials
	matchLine = strings.TrimSpace(strings.ReplaceAll(matchLine, match, "*****"))

	return startLineNum, endLineNum, matchLine
}
