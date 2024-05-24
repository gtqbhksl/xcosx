package all

import (
	_ "xcosx/analyzer/os/release"
	_ "xcosx/analyzer/os/ubuntu"
	_ "xcosx/analyzer/pkg/apk"
	_ "xcosx/analyzer/pkg/dpkg"
	_ "xcosx/analyzer/pkg/rpm"
	_ "xcosx/analyzer/secret"
	_ "xcosx/analyzer/weakpass"
	_ "xcosx/analyzer/webshell"
)
