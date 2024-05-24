package analyzer

type Type string

const (
	// ======
	//   OS
	// ======
	TypeOSRelease Type = "os-release"
	TypeUbuntu    Type = "ubuntu"

	// OS Package
	TypeApk   Type = "apk"
	TypeDpkg  Type = "dpkg"
	TypeRpm   Type = "rpm"
	TypeRpmqa Type = "rpmqa"

	// SSH
	TypeSSH Type = "ssh"
	// Redis
	TypeRedis  Type = "redis"
	TypeTomcat Type = "tomcat"
	TypeMysql  Type = "mysql"

	// =================
	// Structured Config
	// =================
	TypeYaml       Type = "yaml"
	TypeWebshell   Type = "webshell"
	TypeDockerfile Type = "dockerfile"
	TypeTerraform  Type = "terraform"

	// ========
	// Secrets
	// ========
	TypeSecret Type = "secret"
)

var (
	// TypeOSes has all OS-related analyzers
	TypeOSes = []Type{TypeUbuntu,
		TypeApk, TypeDpkg, TypeRpm,
	}

	// TypeLanguages has all language analyzers
	TypeLanguages = []Type{TypeSSH, TypeRedis}
)
