ActiveScan++
==================

ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead, it identifies application behaviour that may be of interest to advanced testers:

  - Potential host header attacks (password reset poisoning, cache poisoning, DNS rebinding)
  - JSONP usage
  - XML input handling
  - Suspicious input transformation (eg 7*7 => '49', \x41\x41 => 'AA')
  - Passive-scanner issues that only occur during fuzzing (install the 'Error Message Checks' extension for maximum effectiveness)

It also adds checks for the following issues:

  - Blind code injection via expression language, Ruby's open()
  - CVE-2014-6271/CVE-2014-6278 'shellshock' and CVE-2015-2080
  
#### Requirements:
Burp Suite Professional (version 1.6 or later)
Jython 2.5 or later standalone: http://www.jython.org/downloads.html

#### Manual installation:

1. 'Extender'->'Options'
2. Click 'Select file' under 'Python environment'
3. Choose jython-standalone-2.5.jar
4. 'Extender'->'Extensions'
5. Click 'Add'
6. Change 'Extension Type' to Python
7. Choose activeScan++.py
8. Done!

#### Usage notes:
To invoke these checks, just run a normal active scan. The JSONP check is part of the passive scanner and always active.

The host header checks tamper with the host header, which may result in requests being routed to different applications on the same host. Exercise caution when running this scanner against applications in a shared hosting environment.

The extension's 'Errors' tab may print 'java.lang.NullPointerException: Request cannot be null.' during active scans. This is a currently unavoidable side effect of the host header attacks, and has no actual impact on the scanner's effectiveness.
    
    
#### Changelog:

**1.0.13 20160120**
  - Harvest additional information on backslash-consumption vulnerabilities
  - Fix bug that reduced efficiency by creating useless insertion points
  - Fix bug that caused passive scanner issues to appear on HTTP instead of HTTPS
  
**1.0.12 - 20151118**
  - Trigger a fresh passive scan when an alternative code path is identified (combines well with the 'Error Message Checks' extension)
  
**1.0.11 - 20150327**
  - Detect misc code injection via suspicious input transformation (eg \x41->A)
  - Report when applications appear to handle XML input
  - Set Connection: close on outgoing requests for speed
  
**1.0.10 - 20150327**
  - Add test for ruby open() exploit - see http://sakurity.com/blog/2015/02/28/openuri.html
  - Assorted minor tweaks and fixes
  
**1.0.9 - 20150225**
  - Add tentative test for CVE-2015-2080
  - Remove dynamic code injection and RPO checks - these are now implemented in core Burp
  - Provide a useful error message when someone foolishly tries using Jython 2.7 beta
  
**1.0.8 - 20141001**
  - Add tentative test for CVE-2014-6278
  
**1.0.7 - 20140926**
  - Tweak test for CVE-2014-6271 for better coverage
  
**1.0.6 - 20140925**
  - Add a test for CVE-2014-6271

**1.0.5 - 20140708**
  - Add compatibility for Jython 2.5 (stable)
  - Improve cache poisoning detection
  - Add a cachebust parameter to prevent accidental cache poisoning
  - Misc. bugfixes
  
**1.0.4 - 20140616**
  - Prevent RPO false positives by checking page's DOCTYPE
  - Reduce host header poisoning false negatives
    
**1.0.3 - 20140523**
  - Prevent duplicate issues when saving/restoring state
  - Refactor: the passive scanner is now almost extensible
  - Improve expression language injection detection
  - Improve RPO regex
  
**1.0.2 - 20140424**
  - Thread safety related bugfixes
  
**1.0.1 - 20140422**
  - Minor bugfixes
  
**1.0:**
  - Release