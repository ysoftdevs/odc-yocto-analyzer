A plugin for OWASP Dependency Check that analyzes IPK files from YOCTO.

Useful for finding known vulnerabilities and licenses.

The plugin automatically suppresses CVEs mentioned in source section, as it expects any mention of a CVE in this section is a patch fixing the CVE.

## Requirements

This plugin calls `tar` and `ar` utilities. You need them on $PATH.

Tested with Debian, but it will likely work with other distributions or even with Windows if these two utilities are on $PATH (or %PATH% :) ).

## Howto

1. Build JAR file using `mvn package`.
2. Add the JAR file to `plugins` directory of OWASP Dependency Check (CLI version).
3. Run the ODC on IPK files with com.ysoft.yocto.enabled=true.