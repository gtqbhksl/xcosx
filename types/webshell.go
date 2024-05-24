package types

type WebshellRuleCategory string

type WebshellFinding struct {
	RuleID    string
	Category  WebshellRuleCategory
	Severity  string
	Title     string
	StartLine int
	EndLine   int
	Match     string
}

type WebshellResult struct {
	FilePath string
	Score    string
	Source   string
}
