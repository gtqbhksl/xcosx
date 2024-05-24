package webshell

import "regexp"
import cm "xcosx/webshell/common"

//rexscan

func init() {

	// TODO: Remove matches item and stick it all under behaviors as nested map[string]map[string]int{} so we can see what the behavior mapped too.

	//// Generics
	cm.GlobalMap.Function_Generics = []cm.RegexDef{{
		Name:        "Generic_URL_Decode",
		Regex:       *regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
		DataCapture: *regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
		PreDecodeActions: []cm.Action{
			{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
			{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
		},
		Functions: []cm.Base_Func{cm.UrlDecode},
	},
		{
			Name:        "Generic_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
		{
			Name:        "Generic_Multiline_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			DataCapture: *regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\r\n", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\n", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\r", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
	}
	cm.GlobalMap.Tags_Generics = []cm.TagDef{
		{
			Name:        "Generic_Execution",
			Description: "Looks for execution associated with web shells",
			Regex:       *regexp.MustCompile(`(?i)(?:\w+\.run\("%comspec% /c)`),
		},
		{
			Name:        "Generic_Webshell_Keywords",
			Description: "Looks for common keywords associated with web shells",
			Regex:       *regexp.MustCompile(`(?i)(?:xp_cmdshell|Database\s+Dump|ShiSanObjstr|Net\s+Sploit|SQLI\+Scan|shell\s?code|envlpass|files?man|c0derz\s?shell|md5\s?cracker|umer\s?rock|asp\s?cmd\s?shell|JspSpy|uZE\s?Shell|AK-74\s?Security\s?Team\s?Web\s?Shell|WinX\s?Shell|PHP C0nsole|cfmshell|cmdshell|Gamma\s?Web\s?Shell|ASPXSpy|IISSpy|Webshell|ASPX?\s?Shell|STNC WebShell|GRP\s?WebShell|National Cracker Crew)`),
		},
		{
			Name:        "Generic_IP/DomainName",
			Description: "Looks for IP addresses or domain names",
			Regex:       *regexp.MustCompile(`(?i)(https?://(?:\d+\.\d+\.\d+\.\d+|\w+(?:\.\w+\.\w+|\.\w+)?)[/\w+\?=\.]+)`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedded_Executable",
			Description: "Looks for magic bytes associated with a PE file",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:0x)?4D5A)`),
		},
		{
			Name:        "Generic_Windows_Reconnaissance",
			Description: "Looks for commands associated with reconnaissance",
			Regex:       *regexp.MustCompile(`(?i)(?:tasklist|netstat|ipconfig|whoami|net\s+(?:localgroup|user)(?:\s|\w)+/add|net\s+start\s+)`),
		},
		{
			Name:        "Generic_Windows_Commands",
			Description: "Looks for calls to commonly used windows binaries",
			Regex:       *regexp.MustCompile(`(?i)(?:[wc]script\.(?:shell|network)|(?:cmd|powershell|[wc]script)(?:\.exe)?|cmd\.exe\s+/c)`),
		},
		{
			Name:        "Generic_Windows_Registry_Persistence",
			Description: "Looks for registry paths associated with Windows persistence mechanisms",
			Regex:       *regexp.MustCompile(`(?i)(?:\\currentversion\\(?:run|runonce))`),
		},
		{
			Name:        "Generic_Defense_Evasion",
			Description: "Looks for registry paths associated with Windows persistence mechanisms",
			Regex:       *regexp.MustCompile(`(?i)(?:strpos\(\$_SERVER\['HTTP_USER_AGENT'\],'Google'\))`),
		},
		{
			Name:        "Generic_Embedding_Code_C",
			Description: "Looks for C code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:include\s<sys/socket\.h>|socket\(AF_INET,SOCK_STREAM|bind\(|listen\(|daemon\(1,0\))`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedding_Code_Perl",
			Description: "Looks for Perl code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:getprotobyname\('tcp'\)|#!/usr/bin/perl)|exec\s+\{'/bin/sh'\}\s+'-bash'`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedding_Code_Python",
			Description: "Looks for Python code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:)#!/usr/bin/python|cgitb\.enable\(\)|print_exc\(|import\ssubprocess|subprocess\.Popen\(|urllib\.urlretrieve\(`),
			Attribute:   true,
		},
	}

	//// PHP
	cm.GlobalMap.Function_Php = []cm.RegexDef{
		{
			Name:        "PHP_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
		{
			Name:        "PHP_GzInflate_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64, cm.GZInflate},
		},
		{
			Name:        "PHP_Url_Decode",
			Regex:       *regexp.MustCompile(`(?i)(urldecode\('?"?[%\w+]+'?"?\))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")'?"?[%\w+]+'?"?)`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.UrlDecode},
		},
		{
			Name:        "PHP_Dot_Concatenation",
			Regex:       *regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			DataCapture: *regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"'.'", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\".\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, {
			Name:        "PHP_CharCode",
			Regex:       *regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|array\((?:\r|\n|\r\n|\n\r|\s+)chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			DataCapture: *regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"chr", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{" ", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{")", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"(", "|", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{",", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []cm.Base_Func{cm.CharDecode}, // looks for strings Split by pipe
		}}
	cm.GlobalMap.Tags_Php = []cm.TagDef{
		{
			Name:        "PHP_Banned_Function",
			Description: "Banned PHP functions are commonly disabled by hosting providers due to security concerns",
			Regex:       *regexp.MustCompile(`(?i)(?:allow_url_fopen\(|fsockopen\(|getrusage\(|get_current_user\(|set_time_limit\(|getmyuid\(|getmypid\(|dl\(|leak\(|listen\(|chown\(|chgrp\(|realpath\(|link\(|exec\(|passthru\(|curl_init\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Reconnaissance",
			Description: "Looks for common PHP functions used for gaining further insight into the environment.",
			Regex:       *regexp.MustCompile(`(?i)(?:@ini_get\("disable_functions"\)|gethostbyname\(|phpversion\(|disk_total_space\(|posix_getpwuid\(|posix_getgrgid\(|phpinfo\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Database_Operations",
			Description: "Looks for common PHP functions used for interacting with a database.",
			Regex:       *regexp.MustCompile(`(?i)(?:'mssql_connect\('|ocilogon\(|mysql_list_dbs\(mysql_num_rows\(|mysql_dbname\(|mysql_create_db\(|mysql_drop_db\(|mysql_query\(|mysql_exec\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Disk_Operations",
			Description: "Looks for common PHP functions used for interacting with a file system.",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:\s|@)rename\(|(%s|@)chmod\(|(%s|@)fileowner\(|(%s|@)filegroup\(|fopen\(|fwrite\(\))`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Execution",
			Description: "Looks for common PHP functions used for executing code.",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:\s|\()(?:curl_exec\(|eval\(|exec\(|shell_exec\(|execute\(|passthru\()|(?:assert|array)\(\$_REQUEST\['?"?\w+"?'?\]|\$\{"?'?_REQUEST'?"?\})`),
		},
		{
			Name:        "PHP_Defense_Evasion",
			Description: "Looks for common PHP functions used for hiding or obfuscating code.",
			Regex:       *regexp.MustCompile(`(?i)(?:gzinflate\(base64_decode\(|preg_replace\(|\(md5\(md5\(\$\w+\))`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Network_Operations",
			Description: "Looks for common PHP functions used for network operations such as call backs",
			Regex:       *regexp.MustCompile(`(?i)(?:fsockopen\()`),
		},
	}

	//// ASP/X
	cm.GlobalMap.Function_Asp = []cm.RegexDef{
		{
			Name:        "ASP_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		}, {
			Name:        "ASP_GzInflate_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64, cm.GZInflate},
		}, {
			Name:        "ASP_Comment_Obfuscation1",
			Regex:       *regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"&\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'&'", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, {
			Name:        "ASP_Comment_Obfuscation2",
			Regex:       *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplaceRegex, Arguments: []interface{}{`(?i)(?:"|')\+\w+\+(?:"|')`, "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"+", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"++\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, { // TODO: Handle vbscript.encode and jsp encoding
			Name:        "ASP_VBScriptEncode",
			Regex:       *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplaceRegex, Arguments: []interface{}{`(?i)(?:"|')\+\w+\+(?:"|')`, "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"+", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"++\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		},
	}
	cm.GlobalMap.Tags_Asp = []cm.TagDef{
		{
			Name:        "ASP_Execution",
			Description: "ASP functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:e["+/*-]+v["+/*-]+a["+/*-]+l["+/*-]+\(|system\.diagnostics\.processstartinfo\(\w+\.substring\(|startinfo\.filename=\"?'?cmd\.exe"?'?|\seval\(request\.item\["?'?\w+"?'?\](?:,"?'?unsafe"?'?)?|execute(?:\(|\s+request\(\"\w+\"\))|RunCMD\(|\seval\(|COM\('?"?WScript\.(?:shell|network)"?'?|response\.write\()`),
		},
		{
			Name:        "Database_Command_Execution",
			Description: "ASP functions associated with code execution using database commands",
			Regex:       *regexp.MustCompile(`(?i)\w+\.(?:ExecuteNonQuery|CreateCommand)\(`),
		},
		{
			Name:        "ASP_Disk_Operations",
			Description: "ASP functions associated with disk operations",
			Regex:       *regexp.MustCompile(`(?i)(?:createtextfile\(|server\.createobject\(\"Scripting\.FileSystemObject\"\))`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Suspicious",
			Description: "ASP code blocks that are suspicious",
			Regex:       *regexp.MustCompile(`(?i)(?:deletefile\(server\.mappath\(\"\w+\.\w+\"\)\)|language\s+=\s+vbscript\.encode\s+%>(?:\s*|\r|\n)<%\s+response\.buffer=true:server\.scripttimeout=|(?i)language\s+=\s+vbscript\.encode%><%\n?\r?server\.scripttimeout=|executeglobal\(|server\.createobject\(\w+\(\w{1,5},\w{1,5}\)\))`),
		},
		{
			Name:        "ASP_Targeted_Object_Creation",
			Description: "ASP object creations commonly leveraged in webshells",
			Regex:       *regexp.MustCompile(`(?i)server\.createobject\(\"(?:msxml2\.xmlhttp|microsoft\.xmlhttp|WSCRIPT\.SHELL|ADODB\.Connection)\"\)`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Suspicious_imports",
			Description: "Looks for imported dependencies that are common with WebShells",
			Regex:       *regexp.MustCompile(`(?i)name(?:space)?="(?:system\.(?:serviceprocess|threading|(?:net\.sockets)))"?"`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Process_Threads",
			Description: "Looks for a new process or thread being leveraged",
			Regex:       *regexp.MustCompile(`(?:new\s+process\(\)|startinfo\.(?:filename|UseShellExecute|Redirect(?:StandardInput|StandardOutput|StandardError)|CreateNoWindow)|WaitForExit())`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Database",
			Description: "Looks for database access, imports and usage",
			Regex:       *regexp.MustCompile(`(?:(?:SqlDataAdapter|SqlConnection|SqlCommand)\(|System\.Data\.SqlClient|System\.Data\.OleDb|OleDbConnection\(\))`),
			Attribute:   true,
		},
	}

	//// JSP
	cm.GlobalMap.Tags_Jsp = []cm.TagDef{
		{
			Name:        "JSP_Execution",
			Description: "JSP functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:runtime\.exec\()`),
		},
	}

	//// CFM
	cm.GlobalMap.Tags_Cfm = []cm.TagDef{
		{
			Name:        "CFM_Execution",
			Description: "CFM functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:"?/c\s+"?'?#?cmd#?'?"?)`),
		},
	}
}

// deepscan
const (
	MaxFileSize   = 10 * 1024 * 1024
	EndSig        = "__WXX__"
	ModuleContent = `
{
  "Layers": [
    {
      "Neurons": [
        {
          "In": [
            {
              "Weight": 0.07802227838030487,
              "IsBias": false
            },
            {
              "Weight": 1.4095429709623049,
              "IsBias": false
            },
            {
              "Weight": 0.38148619141265666,
              "IsBias": false
            },
            {
              "Weight": -6.362409388325939,
              "IsBias": false
            },
            {
              "Weight": 4.080571054281222,
              "IsBias": false
            },
            {
              "Weight": -1.107085408804461,
              "IsBias": false
            },
            {
              "Weight": -2.807126016126731,
              "IsBias": false
            },
            {
              "Weight": -1.9763170163830057,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 2.823264326167646,
              "IsBias": false
            },
            {
              "Weight": -0.6608600824674566,
              "IsBias": false
            },
            {
              "Weight": 2.874326287374728,
              "IsBias": false
            },
            {
              "Weight": 0.08416886315759835,
              "IsBias": false
            },
            {
              "Weight": 0.8153010040531086,
              "IsBias": false
            },
            {
              "Weight": -4.472337116575626,
              "IsBias": false
            },
            {
              "Weight": 0.541617145636806,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": -0.6543721724426969,
              "IsBias": false
            },
            {
              "Weight": -0.11351002316301177,
              "IsBias": false
            },
            {
              "Weight": -2.778411050495509,
              "IsBias": false
            },
            {
              "Weight": -1.5991736481774113,
              "IsBias": false
            },
            {
              "Weight": 0.9136739867878497,
              "IsBias": false
            },
            {
              "Weight": -0.644907220299406,
              "IsBias": false
            },
            {
              "Weight": -0.8640656179897181,
              "IsBias": false
            },
            {
              "Weight": -0.9315779426960278,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": -1.4567022684114097,
              "IsBias": false
            },
            {
              "Weight": -0.6468592746969144,
              "IsBias": false
            },
            {
              "Weight": 0.6201992476017124,
              "IsBias": false
            },
            {
              "Weight": 0.9125011159360927,
              "IsBias": false
            },
            {
              "Weight": 2.607038733396296,
              "IsBias": false
            },
            {
              "Weight": -1.0749890159529927,
              "IsBias": false
            },
            {
              "Weight": -1.0208558454295986,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": -1.1872150471109126,
              "IsBias": false
            },
            {
              "Weight": -7.463649545207768,
              "IsBias": false
            },
            {
              "Weight": 2.541632683678553,
              "IsBias": false
            },
            {
              "Weight": 4.160943382846905,
              "IsBias": false
            },
            {
              "Weight": -2.5973806466094373,
              "IsBias": false
            },
            {
              "Weight": 1.653957746597271,
              "IsBias": false
            },
            {
              "Weight": -6.884847050043971,
              "IsBias": false
            },
            {
              "Weight": -0.2102350505281358,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 2.554024565257,
              "IsBias": false
            },
            {
              "Weight": -8.859300727382568,
              "IsBias": false
            },
            {
              "Weight": 2.124795830106873,
              "IsBias": false
            },
            {
              "Weight": -1.9398906019689914,
              "IsBias": false
            },
            {
              "Weight": -0.4523080851775894,
              "IsBias": false
            },
            {
              "Weight": 1.9595764594365557,
              "IsBias": false
            },
            {
              "Weight": 1.5940597677757709,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": -0.8161856401698268,
              "IsBias": false
            },
            {
              "Weight": 0.3635586661044913,
              "IsBias": false
            },
            {
              "Weight": -0.8561591068732642,
              "IsBias": false
            },
            {
              "Weight": 3.2480544414176213,
              "IsBias": false
            },
            {
              "Weight": 2.7176779107757576,
              "IsBias": false
            },
            {
              "Weight": 2.114108264406231,
              "IsBias": false
            },
            {
              "Weight": -2.7332781368465193,
              "IsBias": false
            },
            {
              "Weight": -1.7746029214858727,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 0.4858741702633786,
              "IsBias": false
            },
            {
              "Weight": -1.9626762022939586,
              "IsBias": false
            },
            {
              "Weight": 1.564911000482225,
              "IsBias": false
            },
            {
              "Weight": -0.5474493229412074,
              "IsBias": false
            },
            {
              "Weight": 0.9770208354067265,
              "IsBias": false
            },
            {
              "Weight": 5.264125280855112,
              "IsBias": false
            },
            {
              "Weight": 0.8485257255411578,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 1.5126562493704359,
              "IsBias": false
            },
            {
              "Weight": 1.163872021778959,
              "IsBias": false
            },
            {
              "Weight": -1.383147543863053,
              "IsBias": false
            },
            {
              "Weight": -0.9361762294091227,
              "IsBias": false
            },
            {
              "Weight": -3.427184157113483,
              "IsBias": false
            },
            {
              "Weight": 1.0491574601330103,
              "IsBias": false
            },
            {
              "Weight": 2.888658925819805,
              "IsBias": false
            },
            {
              "Weight": -0.2488760831751973,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 0.42286271187185837,
              "IsBias": false
            },
            {
              "Weight": 4.420592558849064,
              "IsBias": false
            },
            {
              "Weight": -0.005199491406042553,
              "IsBias": false
            },
            {
              "Weight": -1.8270924471744798,
              "IsBias": false
            },
            {
              "Weight": -1.8412769059668865,
              "IsBias": false
            },
            {
              "Weight": -0.0002618591164747282,
              "IsBias": false
            },
            {
              "Weight": 1.652621845539065,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 0.1508130089938433,
              "IsBias": false
            },
            {
              "Weight": -23.046630100513514,
              "IsBias": false
            },
            {
              "Weight": 6.5465449241651905,
              "IsBias": false
            },
            {
              "Weight": -0.8300577963162118,
              "IsBias": false
            },
            {
              "Weight": 1.1659991302927029,
              "IsBias": false
            },
            {
              "Weight": 3.388516829744258,
              "IsBias": false
            },
            {
              "Weight": 2.560645561046732,
              "IsBias": false
            },
            {
              "Weight": -8.268192950753948,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 2.0967476989197014,
              "IsBias": false
            },
            {
              "Weight": -13.24364434981652,
              "IsBias": false
            },
            {
              "Weight": 0.6450334785481243,
              "IsBias": false
            },
            {
              "Weight": -0.46401719447258427,
              "IsBias": false
            },
            {
              "Weight": 1.2716511370872574,
              "IsBias": false
            },
            {
              "Weight": -9.002423228035425,
              "IsBias": false
            },
            {
              "Weight": 1.177512973282399,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 0.8647526321507062,
              "IsBias": false
            },
            {
              "Weight": 0.8490082021930392,
              "IsBias": false
            },
            {
              "Weight": 0.49293798758077706,
              "IsBias": false
            },
            {
              "Weight": -2.0811563073490933,
              "IsBias": false
            },
            {
              "Weight": 0.10231197547215905,
              "IsBias": false
            },
            {
              "Weight": -0.7495060056871233,
              "IsBias": false
            },
            {
              "Weight": 1.9173447282930045,
              "IsBias": false
            },
            {
              "Weight": 1.9931956279109675,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 0.17944219243805762,
              "IsBias": false
            },
            {
              "Weight": 4.812901564860926,
              "IsBias": false
            },
            {
              "Weight": -0.6599655385106953,
              "IsBias": false
            },
            {
              "Weight": -0.8285849645117789,
              "IsBias": false
            },
            {
              "Weight": -0.5752556075921808,
              "IsBias": false
            },
            {
              "Weight": 0.12363989988964785,
              "IsBias": false
            },
            {
              "Weight": -1.3640735170392506,
              "IsBias": false
            }
          ]
        }
      ],
      "A": 1
    },
    {
      "Neurons": [
        {
          "In": [
            {
              "Weight": 2.823264326167646,
              "IsBias": false
            },
            {
              "Weight": -1.4567022684114097,
              "IsBias": false
            },
            {
              "Weight": 2.554024565257,
              "IsBias": false
            },
            {
              "Weight": 0.4858741702633786,
              "IsBias": false
            },
            {
              "Weight": 0.42286271187185837,
              "IsBias": false
            },
            {
              "Weight": 2.0967476989197014,
              "IsBias": false
            },
            {
              "Weight": 0.17944219243805762,
              "IsBias": false
            },
            {
              "Weight": -1.2094826988114533,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 2.9625838315842685,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": -0.6608600824674566,
              "IsBias": false
            },
            {
              "Weight": -0.6468592746969144,
              "IsBias": false
            },
            {
              "Weight": -8.859300727382568,
              "IsBias": false
            },
            {
              "Weight": -1.9626762022939586,
              "IsBias": false
            },
            {
              "Weight": 4.420592558849064,
              "IsBias": false
            },
            {
              "Weight": -13.24364434981652,
              "IsBias": false
            },
            {
              "Weight": 4.812901564860926,
              "IsBias": false
            },
            {
              "Weight": 5.228805923360504,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": -9.999487077716411,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 2.874326287374728,
              "IsBias": false
            },
            {
              "Weight": 0.6201992476017124,
              "IsBias": false
            },
            {
              "Weight": 2.124795830106873,
              "IsBias": false
            },
            {
              "Weight": 1.564911000482225,
              "IsBias": false
            },
            {
              "Weight": -0.005199491406042553,
              "IsBias": false
            },
            {
              "Weight": 0.6450334785481243,
              "IsBias": false
            },
            {
              "Weight": -0.6599655385106953,
              "IsBias": false
            },
            {
              "Weight": 0.22539821471540675,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 0.9142345072830496,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 0.08416886315759835,
              "IsBias": false
            },
            {
              "Weight": 0.9125011159360927,
              "IsBias": false
            },
            {
              "Weight": -1.9398906019689914,
              "IsBias": false
            },
            {
              "Weight": -0.5474493229412074,
              "IsBias": false
            },
            {
              "Weight": -1.8270924471744798,
              "IsBias": false
            },
            {
              "Weight": -0.46401719447258427,
              "IsBias": false
            },
            {
              "Weight": -0.8285849645117789,
              "IsBias": false
            },
            {
              "Weight": 0.4088587013744612,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": -0.9946146958150462,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 0.8153010040531086,
              "IsBias": false
            },
            {
              "Weight": 2.607038733396296,
              "IsBias": false
            },
            {
              "Weight": -0.4523080851775894,
              "IsBias": false
            },
            {
              "Weight": 0.9770208354067265,
              "IsBias": false
            },
            {
              "Weight": -1.8412769059668865,
              "IsBias": false
            },
            {
              "Weight": 1.2716511370872574,
              "IsBias": false
            },
            {
              "Weight": -0.5752556075921808,
              "IsBias": false
            },
            {
              "Weight": -1.867772136167738,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": -0.6289069630331902,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": -4.472337116575626,
              "IsBias": false
            },
            {
              "Weight": -1.0749890159529927,
              "IsBias": false
            },
            {
              "Weight": 1.9595764594365557,
              "IsBias": false
            },
            {
              "Weight": 5.264125280855112,
              "IsBias": false
            },
            {
              "Weight": -0.0002618591164747282,
              "IsBias": false
            },
            {
              "Weight": -9.002423228035425,
              "IsBias": false
            },
            {
              "Weight": 0.12363989988964785,
              "IsBias": false
            },
            {
              "Weight": -1.7528277681637259,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": -8.924683714488317,
              "IsBias": false
            }
          ]
        },
        {
          "In": [
            {
              "Weight": 0.541617145636806,
              "IsBias": false
            },
            {
              "Weight": -1.0208558454295986,
              "IsBias": false
            },
            {
              "Weight": 1.5940597677757709,
              "IsBias": false
            },
            {
              "Weight": 0.8485257255411578,
              "IsBias": false
            },
            {
              "Weight": 1.652621845539065,
              "IsBias": false
            },
            {
              "Weight": 1.177512973282399,
              "IsBias": false
            },
            {
              "Weight": -1.3640735170392506,
              "IsBias": false
            },
            {
              "Weight": -0.1756287167395903,
              "IsBias": true
            }
          ],
          "Out": [
            {
              "Weight": 2.6923075873996263,
              "IsBias": false
            }
          ]
        }
      ],
      "A": 1
    },
    {
      "Neurons": [
        {
          "In": [
            {
              "Weight": 2.9625838315842685,
              "IsBias": false
            },
            {
              "Weight": -9.999487077716411,
              "IsBias": false
            },
            {
              "Weight": 0.9142345072830496,
              "IsBias": false
            },
            {
              "Weight": -0.9946146958150462,
              "IsBias": false
            },
            {
              "Weight": -0.6289069630331902,
              "IsBias": false
            },
            {
              "Weight": -8.924683714488317,
              "IsBias": false
            },
            {
              "Weight": 2.6923075873996263,
              "IsBias": false
            },
            {
              "Weight": 3.718106292738009,
              "IsBias": true
            }
          ],
          "Out": null
        }
      ],
      "A": 1
    }
  ],
  "Biases": [
    [
      {
        "Weight": -1.9763170163830057,
        "IsBias": true
      },
      {
        "Weight": -0.9315779426960278,
        "IsBias": true
      },
      {
        "Weight": -0.2102350505281358,
        "IsBias": true
      },
      {
        "Weight": -1.7746029214858727,
        "IsBias": true
      },
      {
        "Weight": -0.2488760831751973,
        "IsBias": true
      },
      {
        "Weight": -8.268192950753948,
        "IsBias": true
      },
      {
        "Weight": 1.9931956279109675,
        "IsBias": true
      }
    ],
    [
      {
        "Weight": -1.2094826988114533,
        "IsBias": true
      },
      {
        "Weight": 5.228805923360504,
        "IsBias": true
      },
      {
        "Weight": 0.22539821471540675,
        "IsBias": true
      },
      {
        "Weight": 0.4088587013744612,
        "IsBias": true
      },
      {
        "Weight": -1.867772136167738,
        "IsBias": true
      },
      {
        "Weight": -1.7528277681637259,
        "IsBias": true
      },
      {
        "Weight": -0.1756287167395903,
        "IsBias": true
      }
    ],
    [
      {
        "Weight": 3.718106292738009,
        "IsBias": true
      }
    ]
  ],
  "Config": {
    "Inputs": 7,
    "Layout": [
      7,
      7,
      1
    ],
    "Activation": 1,
    "Mode": 4,
    "Loss": 1,
    "Bias": true
  }
}`
)
