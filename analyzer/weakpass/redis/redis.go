package redis

import (
	"bufio"
	"context"
	"golang.org/x/xerrors"
	"os"
	"regexp"
	"xcosx/analyzer"
	"xcosx/analyzer/weakpass"
	"xcosx/types"
	"xcosx/utils"
)

//func init() {
//	analyzer.RegisterAnalyzer(&RedisWeakPassAnalyzer{})
//}

const version = 1

var requiredFiles = []string{"etc/redis/redis.conf", "etc/redisc.conf"}

func NEWRedisWeakPassAnalyzer() RedisWeakPassAnalyzer {
	return RedisWeakPassAnalyzer{}
}

type RedisWeakPassAnalyzer struct{}

func (a RedisWeakPassAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	//读取用户名和密码
	var records []weakpass.Record

	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {

		t := weakpass.Record{}
		reg := regexp.MustCompile(`(?m)^requirepass\s+[\"|\']?([^(\"|\'|\n)]+)[\"|\']?`)
		result := reg.FindAllStringSubmatch(scanner.Text(), -1)
		for _, passwd := range result {
			if len(passwd) != 2 {
				continue
			}
			t.Username = ""
			t.Password = passwd[1]
			records = append(records, t)
		}
	}

	//对用户名和密码进行弱口令分析
	res, err := weakpass.Analyze(types.Redis, input.FilePath, records)
	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	//fmt.Println("弱口令", res.Weakpasses)
	return res, nil
}

func (a RedisWeakPassAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	//fileName := filepath.Base(filePath)
	//return utils.StringInSlice(fileName, requiredFiles)
	//fmt.Println("redis", filePath, requiredFiles)
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a RedisWeakPassAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedis
}

func (a RedisWeakPassAnalyzer) Version() int {
	return version
}
