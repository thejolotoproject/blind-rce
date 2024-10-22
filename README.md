<h1 class="code-line" data-line-start=0 data-line-end=1 ><a id="Time_Based__Blind_Remote_Code_Execution_RCE_0"></a>Time Based / Blind Remote Code Execution (RCE)</h1>
<p class="has-line-data" data-line-start="4" data-line-end="5">A Python-based program for Time-based/Blind Remote Code Execution (RCE). The main objective of this program is to extract the data that is not visible and/or not returned in the response of vulnerable target. It uses time-based techniques by sending a payload to the target with a command specified and then waiting for its response.</p>
<h5 class="code-line" data-line-start=6 data-line-end=7 ><a id="DEMO_6"></a>DEMO</h5>
<p class="has-line-data" data-line-start="2" data-line-end="3"><a href="thejolotoproject.com"><img src="https://github.com/thejolotoproject/blind-rce/blob/master/docs/demo.gif" alt="N|Solid"></a></p>
<br/>
<p class="has-line-data" data-line-start="10" data-line-end="11">There are two ways to execute.</p>
<p class="has-line-data" data-line-start="10" data-line-end="11">By Arguments:</p>
<pre><code class="has-line-data" data-line-start="13" data-line-end="15" class="language-sh">python rce.py -t <span class="hljs-string">"https://www.site.com?vuln="</span> -c <span class="hljs-string">"whoami"</span> -m <span class="hljs-string">"POST"</span>
</code></pre>
<p class="has-line-data" data-line-start="15" data-line-end="16">By File:</p>
<pre><code class="has-line-data" data-line-start="17" data-line-end="19" class="language-sh">python rce.py <span class="hljs-operator">-f</span> <span class="hljs-string">"/locate/request.txt"</span> -c <span class="hljs-string">"whoami"</span>
</code></pre>
<p class="has-line-data" data-line-start="20" data-line-end="21"><code>/locate/request.txt</code></p>
<blockquote>
<p class="has-line-data" data-line-start="23" data-line-end="36">POST /vuln?x= HTTP/2<br>
Host: <a href="http://site.com">site.com</a><br>
Content-Length: 21<br>
Sec-Ch-Ua-Platform: “Linux”<br>
Accept-Language: en-US,en;q=0.9<br>
Content-Type: application/json<br>
Referer: <a href="https://site.com/vuln?x=">https://site.com/vuln?x=</a><br>
Accept-Encoding: gzip, deflate, br<br>
Priority: u=0, i<br>
{<br>
product_id:“507f1f77bcf86cd799439011”,<br>
category:“bar_foo”,<br>
}</p>
</blockquote>
<p class="has-line-data" data-line-start="37" data-line-end="38">Request Header File. We can get it from our Burpsuite, Caido, Http Header or Tamper…</p>
<br/>
<p class="has-line-data" data-line-start="40" data-line-end="41">Customized headers and the data you want to pass in your request.</p>
<pre><code class="has-line-data" data-line-start="43" data-line-end="45" class="language-sh">python rce.py -t http://site.com/vuln?x= -c <span class="hljs-string">"whoami"</span> -m <span class="hljs-string">"POST"</span> <span class="hljs-operator">-d</span> <span class="hljs-number">10</span> --Headers <span class="hljs-string">"['X-Host: server.example.com', 'Authorization: Bearer eyJhbG']"</span> --json <span class="hljs-string">"{product_id:'507f1f77bcf86cd799439011',category:'bar_foo'}"</span>
</code></pre>
<br/>

<h5 class="code-line" data-line-start=6 data-line-end=7 ><a id="DEMO_6"></a>POC</h5>
<p class="has-line-data" data-line-start="2" data-line-end="3"><a href="thejolotoproject.com"><img src="https://github.com/thejolotoproject/blind-rce/blob/master/docs/poc.jpg" alt="N|Solid"></a></p>
<br/>
<p class="has-line-data" data-line-start="39" data-line-end="40">✨by: thejolotoproject ✨</p>
<h2 class="code-line" data-line-start=41 data-line-end=42 ><a id="License_41"></a>License</h2>
<p class="has-line-data" data-line-start="43" data-line-end="44">MIT</p>
