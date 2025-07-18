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

Test.Summary = 'Testing ATS client inactivity timeout'

ts = Test.MakeATSProcess("ts", enable_tls=True)
if Condition.CurlUsingUnixDomainSocket():
    replay_file = "slow_server_uds.yaml"
else:
    replay_file = "slow_server.yaml"
server = Test.MakeVerifierServerProcess("server", replay_file)

Test.ContinueOnFail = True

ts.addDefaultSSLFiles()

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'http',
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.url_remap.remap_required': 1,
        'proxy.config.http.transaction_no_activity_timeout_in': 2,
        'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
    })

ts.Disk.remap_config.AddLines(
    [
        'map https://www.tls.com/ https://127.0.0.1:{0}'.format(server.Variables.https_port),
        'map / http://127.0.0.1:{0}'.format(server.Variables.http_port),
    ])

ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

#
# Test 1: Verify that server delay does not trigger client activity timeout.
#

# The Proxy Verifier server will delay for 3 seconds before returning a response. This is more than
# the 2 second proxy.config.http.transaction_no_activity_timeout_in (the client inactivity timeout),
# but less than the default 30 second proxy.config.http.transaction_no_activity_timeout_out (server
# inactivity timeout).  These tests therefore exercise that the client inactivity timeout does not
# get applied after the request is sent.  In other words, a slow to respond server should not
# trigger the client inactivity timeout.
tr = Test.AddTestRun("Verify that server delay does not trigger client activity timeout.")
client = tr.AddVerifierClientProcess("client", replay_file, http_ports=[ts.Variables.port], https_ports=[ts.Variables.ssl_port])
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.StartBefore(server)

client.Streams.All += Testers.ContainsExpression('x-response: 1', 'Verify that the first response is received')
client.Streams.All += Testers.ContainsExpression('x-response: 2', 'Verify that the second response is received')
if not Condition.CurlUsingUnixDomainSocket():
    client.Streams.All += Testers.ContainsExpression('x-response: 3', 'Verify that the third response is received')
    client.Streams.All += Testers.ContainsExpression('x-response: 4', 'Verify that the fourth response is received')
    client.Streams.All += Testers.ContainsExpression('x-response: 5', 'Verify that the fifth response is received')
    client.Streams.All += Testers.ContainsExpression('x-response: 6', 'Verify that the sixth response is received')
