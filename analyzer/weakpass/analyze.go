package weakpass

import (
	"xcosx/analyzer"
	"xcosx/types"
)

// Record 从文件中解析出来的相关信息
type Record struct {
	Username string
	Password string
	// 除用户名密码外, 有些模块有其他属性
	// 可以记录在此map中
	Attributes map[string]string
}

func Analyze(fileType, filePath string, recrods []Record) (*analyzer.AnalysisResult, error) {

	//根据filetype，导入指定的弱密码规则
	var WeakPassRulesMap = map[string][]Record{
		"ssh":    sshrules,
		"redis":  redisrules,
		"tomcat": tomcatrules,
		"mysql":  mysqlrules,
	}

	expectRecords := WeakPassRulesMap[fileType]

	//匹配到的弱口令数组
	var apps []types.Weakpass

	for _, record := range recrods {
		for _, expectRecord := range expectRecords {
			if record.Password == expectRecord.Password {
				app := types.Weakpass{
					Type:     fileType,
					FilePath: filePath,
					Username: record.Username,
					Password: record.Password,
				}
				apps = append(apps, app)
			}
		}
	}

	return &analyzer.AnalysisResult{Weakpasses: apps}, nil
}
