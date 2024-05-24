package webshell

import (
	"encoding/json"
	"fmt"
	"github.com/patrikeh/go-deep"
	"regexp"
	"strings"
	"xcosx/analyzer/webshell/core"
	"xcosx/types"
	cm "xcosx/webshell/common"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	*Global
}

func NewScanner(configPath string) (Scanner, error) {
	////设置默认规则文件
	global := Global{}
	return Scanner{Global: &global}, nil
}

type Global struct {
	AllowRules   AllowRules
	ExcludeBlock ExcludeBlock
}

type AllowRules []AllowRule

type AllowRule struct {
	ID          string  `yaml:"id"`
	Description string  `yaml:"description"`
	Regex       *Regexp `yaml:"regex"`
	Path        *Regexp `yaml:"path"`
}

// Regexp adds unmarshalling from YAML for regexp.Regexp
type Regexp struct {
	*regexp.Regexp
}
type ExcludeBlock struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func (s Scanner) Scan(args ScanArgs) types.WebshellResult {
	rexresult := rexscan(args.FilePath, args.Content)
	if len(rexresult.FilePath) == 0 {
		deepresult := DeepScanner(args.FilePath, args.Content)
		if len(deepresult.FilePath) > 0 {

			return types.WebshellResult{
				FilePath: deepresult.FilePath,
				Score:    deepresult.Score,
				Source:   deepresult.Source,
			}
		} else {
			return types.WebshellResult{}
		}
	} else {

		return types.WebshellResult{
			FilePath: rexresult.FilePath,
			Score:    rexresult.Score,
			Source:   rexresult.Source,
		}
	}

}

func DeepScanner(obj string, content []byte) types.WebshellResult {

	dn := deep.NewNeural(&deep.Config{
		Inputs:     7,
		Layout:     []int{7, 7, 1},
		Activation: deep.ActivationSigmoid,
		Mode:       deep.ModeMultiLabel,
		Weight:     deep.NewNormal(1.0, 0.0),
		Bias:       true,
	})
	err := json.Unmarshal([]byte(ModuleContent), dn)
	if err != nil {
		fmt.Printf("Unmarshal module error: %v \n", err)
	}

	plugins := core.GetPlugins()
	calculators := core.GetCalculators()

	results := make(map[string]string)

	var param []float64
	contentStr := string(content)
	_, t := core.CheckRegexMatches(plugins, contentStr, obj)
	param = append(param, t)
	for _, calculator := range calculators {
		param = append(param, calculator.Uniformization(contentStr))
	}
	results[obj] = fmt.Sprintf("%.2f", dn.Predict(param)[0]*100)
	//fmt.Println(results[obj])
	if strings.Compare(results[obj], "0") > 0 {
		content, _ = json.Marshal(results)
		return types.WebshellResult{
			FilePath: obj,
			Score:    results[obj],
			Source:   "Neural Networks",
		}
	} else {
		return types.WebshellResult{}
	}
}

func rexscan(file string, content []byte) types.WebshellResult {
	fileExt := file[len(file)-4:]

	matches, functions, tags := cm.ProcessFileData(string(content), strings.ToLower(fileExt))
	Jdata := cm.FileObj{}
	Jdata.FilePath = file
	Jdata.Matches = matches
	Jdata.Attributes = tags
	Jdata.Decodes = functions
	if len(Jdata.Matches) > 0 {
		return types.WebshellResult{
			FilePath: file,
			Score:    "100",
			Source:   "Regular expression",
		}
	} else {
		return types.WebshellResult{}
	}
}
