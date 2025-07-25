'''
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import sys

Test.Summary = '''
Test a basic remap of a http/2 connection
'''

Test.SkipUnless(Condition.HasCurlFeature('http2'))
Test.ContinueOnFail = True

# ----
# Setup Origin Server
# ----
server = Test.MakeOriginServer("server")

# For Test Case 1 & 5 - /
server.addResponse(
    "sessionlog.json", {
        "headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    })

# For Test Case 2 - /bigfile
# Add info for the large H2 download test
server.addResponse(
    "sessionlog.json", {
        "headers": "GET /bigfile HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Length: 191414\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    })

# For Test Case 3 - /test2
server.addResponse(
    "sessionlog.json", {
        "headers": "GET /test2 HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    })

# For Test Case 6 - /postchunked
post_body = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
server.addResponse(
    "sessionlog.json", {
        "headers": "POST /postchunked HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": post_body
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nContent-Length: 10\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "0123456789"
    })

# For Test Case 7 - /bigpostchunked
# Make a post body that will be split across at least two frames
big_post_body = "0123456789" * 131070
server.addResponse(
    "sessionlog.json", {
        "headers": "POST /bigpostchunked HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": big_post_body
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nContent-Length: 10\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "0123456789"
    })

big_post_body_file = open(os.path.join(Test.RunDirectory, "big_post_body"), "w")
big_post_body_file.write(big_post_body)
big_post_body_file.close()

# For Test Case 8 - /huge_resp_hdrs
server.addResponse(
    "sessionlog.json", {
        "headers": "GET /huge_resp_hdrs HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nContent-Length: 6\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "200 OK"
    })

# For Test Case 9 - /status/204
server.addResponse(
    "sessionlog.json", {
        "headers": "GET /status/204 HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 204 No Content\r\nServer: microserver\r\nConnection: close\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    })

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)

# add ssl materials like key, certificates for the server
ts.addDefaultSSLFiles()

ts.Setup.CopyAs('rules/huge_resp_hdrs.conf', Test.RunDirectory)
ts.Disk.remap_config.AddLine(
    'map /huge_resp_hdrs http://127.0.0.1:{0}/huge_resp_hdrs @plugin=header_rewrite.so @pparam={1}/huge_resp_hdrs.conf '.format(
        server.Variables.Port, Test.RunDirectory))

ts.Disk.remap_config.AddLine('map / http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'http',
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.http2.active_timeout_in': 3,
        'proxy.config.http2.max_concurrent_streams_in': 65535,
    })

ts.Setup.CopyAs('h2client.py', Test.RunDirectory)
ts.Setup.CopyAs('h2active_timeout.py', Test.RunDirectory)

# ----
# Test Cases
# ----

# Test Case 1:  basic H2 interaction
tr = Test.AddTestRun("basic H2 interaction")
tr.Processes.Default.Command = f'{sys.executable} h2client.py {ts.Variables.ssl_port} / --verify_default_body'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.Streams.stdout = "gold/remap-200.gold"
tr.StillRunningAfter = server

# Test Case 2: Make sure all the big file gets back.  Regression test for issue 1646
tr = Test.AddTestRun("big file download")
tr.Processes.Default.Command = f'{sys.executable} h2client.py {ts.Variables.ssl_port} /bigfile --repeat 2 --verify_default_body'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/bigfile.gold"
tr.StillRunningAfter = server

# Test Case 3: Chunked content
tr = Test.AddTestRun("chunked content")
tr.Processes.Default.Command = f'{sys.executable} h2client.py {ts.Variables.ssl_port} /test2 --print_body'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/chunked.gold"
tr.StillRunningAfter = server

# NOTE: Skipping this test run because traffic-replay doesn't currently support H2
# Test Case 4: Multiple request
# client_path = os.path.join(Test.Variables.AtsTestToolsDir, 'traffic-replay/')
# tr = Test.AddTestRun("multiple request")
# tr.Processes.Default.Command = \
#     (f"{sys.executable} {client_path} -type h2 -log_dir {server.Variables.DataDir} "
#      f"-port {ts.Variables.port} -host '127.0.0.1' -s_port {ts.Variables.ssl_port} -v -colorize False")
# tr.Processes.Default.ReturnCode = 0
# tr.Processes.Default.Streams.stdout = "gold/replay.gold"
# tr.StillRunningAfter = server

# Test Case 5: h2_active_timeout
tr = Test.AddTestRun("h2_active_timeout")
tr.Processes.Default.Command = f'{sys.executable} h2active_timeout.py {ts.Variables.ssl_port} / 4'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = "gold/active_timeout.gold"
tr.StillRunningAfter = server

# Test Case 6: Post with chunked body
# While HTTP/2 does not support Transfer-encoding we pass that into curl to encourage it to not set the content length
# on the post body
tr = Test.AddTestRun("post with chunked body")
tr.MakeCurlCommand(
    '-s -k -H "Transfer-Encoding: chunked" -d "{0}" https://127.0.0.1:{1}/postchunked'.format(post_body, ts.Variables.ssl_port),
    ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = "gold/post_chunked.gold"
tr.StillRunningAfter = server

# Test Case 7: Post with big chunked body
# While HTTP/2 does not support Transfer-encoding we pass that into curl to encourage it to not set the content length
# on the post body
tr = Test.AddTestRun("post with big chunked body")
tr.MakeCurlCommand(
    '-s -k -H "Transfer-Encoding: chunked" -d @big_post_body https://127.0.0.1:{0}/bigpostchunked'.format(ts.Variables.ssl_port),
    ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = "gold/post_chunked.gold"
tr.StillRunningAfter = server

# Test Case 8: Huge response header
tr = Test.AddTestRun("huge response header")
# Different versions of curl have "bytes data" at various places in the output.
# Normalize them by simply filtering out those lines since they are not
# important to this test.
tr.MakeCurlCommand(f'-vs -k --http2 https://127.0.0.1:{ts.Variables.ssl_port}/huge_resp_hdrs |& grep -v "bytes data"', ts=ts)
tr.Processes.Default.ReturnCode = 0
# Different versions of curl will have different cases for HTTP/2 field names.
tr.Processes.Default.Streams.stdout = Testers.GoldFile("gold/http2_8_stdout.gold", case_insensitive=True)
tr.StillRunningAfter = server

# Test Case 9: Header Only Response - e.g. 204
tr = Test.AddTestRun("header only response")
tr.MakeCurlCommand('-vs -k --http2 https://127.0.0.1:{0}/status/204'.format(ts.Variables.ssl_port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/http2_9_stdout.gold"
# Different versions of curl will have different cases for HTTP/2 field names.
tr.Processes.Default.Streams.stderr = Testers.GoldFile("gold/http2_9_stderr.gold", case_insensitive=True)
tr.StillRunningAfter = server
