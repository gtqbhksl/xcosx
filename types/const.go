package types

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2
)

const (
	// Programming language dependencies
	Bundler  = "bundler"
	GemSpec  = "gemspec"
	Composer = "composer"
	SSH      = "ssh"
	Redis    = "redis"
	Tomcat   = "tomcat"
	Mysql    = "mysql"
	Jar      = "jar"
	GoBinary = "gobinary"

	// Config files
	WEB            = "web"
	YAML           = "yaml"
	JSON           = "json"
	Dockerfile     = "dockerfile"
	Terraform      = "terraform"
	CloudFormation = "cloudformation"
	Kubernetes     = "kubernetes"
	Helm           = "helm"
	Rbac           = "rbac"

	// Language-specific file names
	NuGetPkgsLock   = "packages.lock.json"
	NuGetPkgsConfig = "packages.config"

	GoMod = "go.mod"
	GoSum = "go.sum"

	MavenPom = "pom.xml"

	NpmPkgLock = "package-lock.json"
	YarnLock   = "yarn.lock"

	ComposerLock = "composer.lock"

	PipRequirements = "requirements.txt"
	PipfileLock     = "Pipfile.lock"
	PoetryLock      = "poetry.lock"

	GemfileLock = "Gemfile.lock"

	CargoLock = "Cargo.lock"
)
