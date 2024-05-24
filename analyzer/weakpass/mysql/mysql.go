package mysql

import (
	"context"
	"golang.org/x/xerrors"
	"os"
	"strings"
	"xcosx/analyzer"
	"xcosx/analyzer/weakpass"
	"xcosx/types"
	"xcosx/utils"
)

const version = 1

var requiredFiles = []string{"var/lib/mysql/mysql.ibd", "var/lib/mysql/mysql2.ibd"}

func NEWMysqlWeakPassAnalyzer() MysqlWeakPassAnalyzer {
	return MysqlWeakPassAnalyzer{}
}

type MysqlWeakPassAnalyzer struct{}

func (a MysqlWeakPassAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	//读取用户名和密码
	var records []weakpass.Record
	page, err := FindUserPage(input.Content)
	if err != nil {
		return &analyzer.AnalysisResult{}, err
	}

	mysqlInfos, err := ParseUserPage(page.Pagedata)
	if err != nil {
		return &analyzer.AnalysisResult{}, err
	}
	tmp := weakpass.Record{}
	for _, info := range mysqlInfos {
		if strings.Contains(info.Password, EmptyPasswordPlaceholder) {
			continue
		}
		if info.Plugin != PluginNameNative {
			tmp.Password = info.Password
		} else {
			tmp.Password = strings.ToLower(info.Password)
		}
		tmp.Username = info.Name
		records = append(records, tmp)
		//fmt.Println(tmp)
	}
	//对用户名和密码进行弱口令分析
	res, err := weakpass.Analyze(types.Mysql, input.FilePath, records)
	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	return res, nil
}

func (a MysqlWeakPassAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a MysqlWeakPassAnalyzer) Type() analyzer.Type {
	return analyzer.TypeMysql
}

func (a MysqlWeakPassAnalyzer) Version() int {
	return version
}
