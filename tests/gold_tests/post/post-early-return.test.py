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

# ----
# Setup Test
# ----
Test.Summary = '''
Test a case when the origin returns before the post is completed
'''
Test.SkipIf(Condition.CurlUsingUnixDomainSocket())
Test.ContinueOnFail = True

Test.GetTcpPort("upstream_port1")
Test.GetTcpPort("upstream_port2")
Test.GetTcpPort("upstream_port3")
Test.GetTcpPort("upstream_port4")
Test.GetTcpPort("upstream_port5")
Test.GetTcpPort("upstream_port6")

# ----
# Setup ATS
# ----
ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)

# add ssl materials like key, certificates for the server
ts.addDefaultSSLFiles()

ts.Disk.remap_config.AddLines(
    [
        'map /one http://127.0.0.1:{0}'.format(Test.Variables.upstream_port1),
        'map /two http://127.0.0.1:{0}'.format(Test.Variables.upstream_port2),
        'map /three http://127.0.0.1:{0}'.format(Test.Variables.upstream_port3),
        'map /four http://127.0.0.1:{0}'.format(Test.Variables.upstream_port4),
        'map /five http://127.0.0.1:{0}'.format(Test.Variables.upstream_port5),
        'map /six http://127.0.0.1:{0}'.format(Test.Variables.upstream_port6),
    ])
ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')
ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.diags.debug.enabled': 0,
        # 'proxy.config.http2.initial_window_size_in': 2*16384, # Make a ludacrisly small window
        'proxy.config.diags.debug.tags': 'http',
    })

server1 = Test.Processes.Process(
    "server1", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port1))
server2 = Test.Processes.Process(
    "server2", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port2))
server3 = Test.Processes.Process(
    "server3", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port3))
server4 = Test.Processes.Process(
    "server4", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port4))
server5 = Test.Processes.Process(
    "server5", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port5))
server6 = Test.Processes.Process(
    "server6", "bash -c '" + Test.TestDirectory + "/server1.sh {} outserver1'".format(Test.Variables.upstream_port6))

big_post_body = "0123456789" * 231070
big_post_body_file = open(os.path.join(Test.RunDirectory, "big_post_body"), "w")
big_post_body_file.write(big_post_body)
big_post_body_file.close()

# First two cases we are using curl with no means to delay the post body.  Even for the large body case, it looks like ATS processes the entire body before getting the response header
# The third case has an explicit multi-second sleep which ensures the early response path is exercised
test_run = Test.AddTestRun("http1.1 Post with small body early return")
test_run.Processes.Default.StartBefore(Test.Processes.ts)
test_run.Processes.Default.StartBefore(server1)
test_run.MakeCurlCommand(
    '-v -o /dev/null --http1.1 -d "small body" -k https://127.0.0.1:{}/one'.format(ts.Variables.ssl_port), ts=ts)
test_run.Processes.Default.Streams.All = Testers.ContainsExpression("HTTP/1.1 420 Be Calm", "Receive the early response")
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0

test_run = Test.AddTestRun("http1.1 Post with large body early return")
test_run.Processes.Default.StartBefore(server2)
test_run.MakeCurlCommand(
    '-H "Expect:" -v -o /dev/null --http1.1 -d @big_post_body -k https://127.0.0.1:{}/two'.format(ts.Variables.ssl_port), ts=ts)
test_run.Processes.Default.Streams.All = Testers.ContainsExpression("HTTP/1.1 420 Be Calm", "Receive the early response")
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0

test_run = Test.AddTestRun("http2 Post with large body, small window and early return")
test_run.Processes.Default.StartBefore(server3)
test_run.MakeCurlCommand(
    '-v -o /dev/null --http2 -d @big_post_body -k https://127.0.0.1:{}/three'.format(ts.Variables.ssl_port), ts=ts)
test_run.Processes.Default.Streams.All = Testers.ContainsExpression("HTTP/2 420", "Receive the early response")
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0

client_out = Test.Disk.File("clientout")
client_out.Content = Testers.ExcludesExpression("0123456789", "The delayed body is not sent")
client_out.Content += Testers.ContainsExpression("HTTP/1.1 420 Be Calm", "Receive the early response")
client_out.Content += Testers.ContainsExpression("Connection: close", "ATS marks the client connection to close")

client_out2 = Test.Disk.File("clientout2")
client_out2.Content = Testers.ExcludesExpression("0123456789", "The delayed body is not sent")
client_out2.Content += Testers.ContainsExpression("HTTP/1.1 420 Be Calm", "Receive the early response")
client_out2.Content += Testers.ContainsExpression("Connection: close", "ATS marks the client connection to close")

client_out3 = Test.Disk.File("clientout3")
client_out3.Content = Testers.ExcludesExpression("0123456789", "The delayed body is not sent")
client_out3.Content += Testers.ContainsExpression("HTTP/1.1 420 Be Calm", "Receive the early response")
client_out3.Content += Testers.ContainsExpression("Connection: close", "ATS marks the client connection to close")

test_run = Test.AddTestRun("http1.1 Post with paused body")
test_run.Processes.Default.StartBefore(server4)
test_run.Setup.Copy("delay_client.sh")
test_run.Processes.Default.Command = "sh ./delay_client.sh {} clientout".format(ts.Variables.port)
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0

test_run = Test.AddTestRun("http1.1 Post with delayed and paused body")
test_run.Processes.Default.StartBefore(server5)
test_run.Setup.Copy("delay_client2.sh")
test_run.Processes.Default.Command = "sh ./delay_client2.sh {} clientout2".format(ts.Variables.port)
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0

test_run = Test.AddTestRun("http1.1 Post with paused body and no delay on server")
test_run.Processes.Default.StartBefore(server6)
test_run.Setup.Copy("delay_client3.sh")
test_run.Processes.Default.Command = "sh ./delay_client3.sh {} clientout3".format(ts.Variables.port)
test_run.StillRunningAfter = ts
test_run.Processes.Default.ReturnCode = 0
