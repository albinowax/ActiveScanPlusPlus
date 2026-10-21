package burp;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.PerHostScans.htmlEncode;
import static burp.PerHostScans.safeBytesToString;

public class Php2Shell extends ParamScan {

    private static final Pattern PHP_VERSION_TOKEN = Pattern.compile("(?<![A-Za-z0-9])PHP/(\\d+)\\.(\\d+)(?:\\.(\\d+))?([^\\s;,()]*)", Pattern.CASE_INSENSITIVE);

    private static final Pattern PRE_RELEASE_SUFFIX = Pattern.compile("^-?(alpha|beta|rc|dev)", Pattern.CASE_INSENSITIVE);

    private static final Map<String, Integer> FIXED_PATCH_BY_BRANCH = Map.of("8.2", 35, "8.3", 36, "8.4", 27, "8.5", 12);

    private static final Set<String> reportedServices = ConcurrentHashMap.newKeySet();

    Php2Shell(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse basePair) {
        if (basePair.getResponse() == null) {
            return Collections.emptyList();
        }

        List<String> headers = Utilities.helpers.analyzeResponse(basePair.getResponse()).getHeaders();
        for (String headerName : List.of("X-Powered-By:", "Server:")) {
            for (String header : headers) {
                Matcher version = PHP_VERSION_TOKEN.matcher(header);
                if (header.regionMatches(true, 0, headerName, 0, headerName.length()) && version.find()) {
                    return isAffected(version) && reportedServices.add(serviceKey(basePair.getHttpService()))
                            ? List.of(createIssue(basePair, header, version.group()))
                            : Collections.emptyList();
                }
            }
        }
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        return Collections.emptyList();
    }

    private static String serviceKey(IHttpService service) {
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    private static boolean isAffected(Matcher version) {
        int major = Integer.parseInt(version.group(1));
        int minor = Integer.parseInt(version.group(2));
        if (major < 8 || major == 8 && minor < 2) {
            return true;
        }

        Integer fixedPatch = FIXED_PATCH_BY_BRANCH.get(major + "." + minor);
        if (fixedPatch == null || version.group(3) == null) {
            return false;
        }

        int patch = Integer.parseInt(version.group(3));
        return patch < fixedPatch || patch == fixedPatch && PRE_RELEASE_SUFFIX.matcher(version.group(4)).find();
    }

    private IScanIssue createIssue(IHttpRequestResponse basePair, String header, String version) {
        String detail = "<p>The server discloses a PHP version that is vulnerable to <b>CVE-2026-109618</b> and " +
                       "<b>CVE-2026-109619</b> (PHP2Shell), critical remote code execution vulnerabilities in the PHP " +
                       "interpreter with a CVSS v4.0 score of 9.2.</p>" +
                       "<p><b>Vulnerability Overview:</b></p>" +
                       "<ul>" +
                       "<li>Unauthenticated remote code execution with the privileges of the PHP process</li>" +
                       "<li>CVE-2026-109618: out-of-memory handling can interrupt PHP while internal request data is only " +
                       "partly initialised, and request cleanup then treats the invalid data as valid</li>" +
                       "<li>CVE-2026-109619: request-owned state can survive after its memory has been freed, and a later " +
                       "request handled by the same worker can use that stale state</li>" +
                       "<li>Affects every PHP installation that serves web requests, including PHP-FPM, Apache with mod_php, " +
                       "php-cgi, FrankenPHP and LiteSpeed</li>" +
                       "<li>On Apache with mod_php, the attack can be triggered before any application code runs</li>" +
                       "</ul>" +
                       "<p><b>Detection Evidence:</b></p>" +
                       "<ul>" +
                       "<li>The highlighted response header discloses <b>" + htmlEncode(version) + "</b></li>" +
                       "<li>Burp identified the PHP version from a response header, and did not test for the vulnerability</li>" +
                       "<li>Linux distributions often backport security fixes without changing the version string, so a " +
                       "patched server can disclose a vulnerable version</li>" +
                       "</ul>" +
                       "<p><b>CRITICAL - Immediate Action Required</b></p>" +
                       "<p>This vulnerability allows unauthenticated attackers to execute arbitrary code on the server. Patch immediately.</p>" +
                       "<p><b>Upgrade to Patched Versions:</b></p>" +
                       "<ul>" +
                       "<li><b>PHP 8.5:</b> 8.5.12</li>" +
                       "<li><b>PHP 8.4:</b> 8.4.27</li>" +
                       "<li><b>PHP 8.3:</b> 8.3.36</li>" +
                       "<li><b>PHP 8.2:</b> 8.2.35</li>" +
                       "<li><b>PHP 8.1 and earlier:</b> no longer receive releases from the PHP project. Use a backported " +
                       "fix from your distribution or LTS vendor, the PHP security team's source backports for PHP 7.4, 8.0 " +
                       "or 8.1, or upgrade to a supported branch</li>" +
                       "</ul>" +
                       "<p><b>Remediation Steps:</b></p>" +
                       "<ol>" +
                       "<li>If PHP is installed from a distribution package, check the package changelog for CVE-2026-109618 " +
                       "and CVE-2026-109619 to confirm whether the fix has been backported</li>" +
                       "<li>Otherwise, upgrade PHP to a patched version</li>" +
                       "<li>Restart every PHP worker, such as PHP-FPM pools and Apache</li>" +
                       "<li>Set expose_php = Off and, on Apache, ServerTokens Prod, so that the server stops disclosing its PHP version</li>" +
                       "</ol>" +
                       "<p><b>Partial Mitigations:</b></p>" +
                       "<p>Until you can upgrade, the PHP security advisory lists configuration changes that reduce exposure " +
                       "to specific attack paths, such as setting session.upload_progress.enabled to 0. These changes do not " +
                       "make an installation safe.</p>" +
                       "<p><b>References:</b></p>" +
                       "<ul>" +
                       "<li><a href=\"https://www.php.net/archive/2026.php#2026-10-21-5\">PHP Security Advisory</a></li>" +
                       "<li><a href=\"https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w\">CVE-2026-109618 Details</a></li>" +
                       "<li><a href=\"https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp\">CVE-2026-109619 Details</a></li>" +
                       "</ul>" +
                       "<p><b>Vulnerability classifications:</b></p>" +
                       "<ul>" +
                       "<li><a href=\"https://cwe.mitre.org/data/definitions/416.html\">CWE-416: Use After Free</a></li>" +
                       "<li><a href=\"https://cwe.mitre.org/data/definitions/755.html\">CWE-755: Improper Handling of Exceptional Conditions</a></li>" +
                       "</ul>";

        return new CustomScanIssue(
                basePair.getHttpService(),
                Utilities.helpers.analyzeRequest(basePair).getUrl(),
                new IHttpRequestResponse[]{highlightResponseHeader(basePair, header)},
                "CVE-2026-109618 / CVE-2026-109619 PHP2Shell (vulnerable PHP version)",
                detail,
                "Tentative",
                CustomScanIssue.severity.High
        );
    }

    private IHttpRequestResponse highlightResponseHeader(IHttpRequestResponse basePair, String headerLine) {
        int start = safeBytesToString(basePair.getResponse()).indexOf(headerLine);
        if (start < 0) {
            return basePair;
        }
        List<int[]> responseMarkers = Collections.singletonList(new int[]{start, start + headerLine.length()});
        return Utilities.callbacks.applyMarkers(basePair, null, responseMarkers);
    }
}
