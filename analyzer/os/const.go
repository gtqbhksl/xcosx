package os

import "golang.org/x/xerrors"

const (
	// openEuler
	OpenEuler = "openEuler"

	//alinos
	Alinos = "alinos"

	// Ubuntu is done
	Ubuntu = "ubuntu"
)

var AnalyzeOSError = xerrors.New("无法识别操作系统信息")
