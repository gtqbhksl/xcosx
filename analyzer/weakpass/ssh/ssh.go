package ssh

import (
	"bufio"
	"context"
	"golang.org/x/xerrors"
	"os"
	"strings"
	"xcosx/analyzer/weakpass"

	"xcosx/analyzer"
	"xcosx/types"
	"xcosx/utils"
)

//func init() {
//	analyzer.RegisterAnalyzer(&SSHWeakPassAnalyzer{})
//}

const version = 1

var requiredFiles = []string{"etc/shadow", "etc/passwd"}

type SSHWeakPassAnalyzer struct{}

func NEWSSHWeakPassAnalyzer() SSHWeakPassAnalyzer {
	return SSHWeakPassAnalyzer{}
}

func (a SSHWeakPassAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	//读取用户名和密码
	var records []weakpass.Record

	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		userinfo := strings.Split(scanner.Text(), ":")
		if len(userinfo) != 9 {
			//xerrors.Error("service: shadow format error")
			continue
		}
		s := weakpass.Record{}
		s.Username = userinfo[0]
		s.Password = userinfo[1]
		records = append(records, s)
	}

	//对用户名和密码进行弱口令分析
	res, err := weakpass.Analyze(types.SSH, input.FilePath, records)
	//fmt.Println(res)
	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	return res, nil
}

func (a SSHWeakPassAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	//fileName := filepath.Base(filePath)
	//return utils.StringInSlice(fileName, requiredFiles)
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a SSHWeakPassAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSSH
}

func (a SSHWeakPassAnalyzer) Version() int {
	return version
}
