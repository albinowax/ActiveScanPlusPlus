ActiveScan++
==================

ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead, it adds checks for the following issues:

  - Dynamic code injection (PHP/Perl/Ruby's eval(), expression language injection)
  - Host header attacks (password reset poisoning, cache poisoning, DNS rebinding)
  - OS command injection (designed to complement Burp's coverage)
  - Relative Path Overwrite
    
Rather than risking numerous false negatives by attempting to automate Relative Path Overwrite and Host header attacks from start to finish, it identifies key vulnerability components and flags these for user review. 

#### Manual installation:

1. 'Extender'->'Options'
2. Click 'Select file' under 'Python environment'
3. Choose jython-standalone-2.7-b1.jar
4. 'Extender'->'Extensions'
5. Click 'Add'
6. Change 'Extension Type' to Python
7. Choose activeScan++.py
8. Done!

#### Usage notes:
To invoke these checks, just run a normal active scan. The Relative Path Overwrite check is part of the passive scanner and always active.

The host header checks tamper with the host header, which may result in requests being routed to different applications on the same host. Exercise caution when running this scanner against applications in a shared hosting environment.

The extension's 'Errors' tab may print 'java.lang.NullPointerException: Request cannot be null.' during active scans. This is a currently unavoidable side effect of the host header attacks, and has no actual effort on the scanner's effectiveness.
    
    
#### Changelog:  
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