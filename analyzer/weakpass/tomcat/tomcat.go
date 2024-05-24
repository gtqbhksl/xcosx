package tomcat

import (
	"context"
	"fmt"
	"github.com/beevik/etree"
	"golang.org/x/xerrors"
	"os"
	"xcosx/analyzer"
	"xcosx/analyzer/weakpass"
	"xcosx/types"
	"xcosx/utils"
)

const version = 1

var requiredFiles = []string{"usr/local/tomcat/conf/tomcat-users.xml", "etc/redis/tomcat-users.xml"}

func NEWTomcatWeakPassAnalyzer() TomcatWeakPassAnalyzer {
	return TomcatWeakPassAnalyzer{}
}

type TomcatWeakPassAnalyzer struct{}

func (a TomcatWeakPassAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	//读取用户名和密码
	var records []weakpass.Record
	doc := etree.NewDocument()
	if _, err := doc.ReadFrom(input.Content); err != nil {
		fmt.Println(err)
	}
	root := doc.SelectElement("tomcat-users")
	if root == nil {
		return &analyzer.AnalysisResult{}, nil
	}
	token := root.FindElements("user")
	if len(token) == 0 {
		return &analyzer.AnalysisResult{}, nil
	}
	t := weakpass.Record{}
	for _, res := range token {
		t.Username = res.SelectAttr("username").Value
		t.Password = res.SelectAttr("password").Value
		records = append(records, t)
	}

	//对用户名和密码进行弱口令分析
	res, err := weakpass.Analyze(types.Tomcat, input.FilePath, records)
	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	//fmt.Println("弱口令", res.Weakpasses)
	return res, nil
}

func (a TomcatWeakPassAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	//fileName := filepath.Base(filePath)
	//return utils.StringInSlice(fileName, requiredFiles)
	//fmt.Println("redis", filePath, requiredFiles)
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a TomcatWeakPassAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTomcat
}

func (a TomcatWeakPassAnalyzer) Version() int {
	return version
}
