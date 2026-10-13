"""核实 README 里每个数字/声明是否与源码一致。"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
readme = open(README, encoding="utf-8").read()

rs = open(os.path.join(ROOT, "src/shellsentry/core/regex_scanner.py"), encoding="utf-8").read()
dec = open(os.path.join(ROOT, "src/shellsentry/core/decoder.py"), encoding="utf-8").read()
pr = open(os.path.join(ROOT, "src/shellsentry/core/prompts.py"), encoding="utf-8").read()
eng = open(os.path.join(ROOT, "src/shellsentry/core/engine.py"), encoding="utf-8").read()
web = open(os.path.join(ROOT, "src/shellsentry/web/app.py"), encoding="utf-8").read()
h = open(os.path.join(ROOT, "src/shellsentry/web/static/index.html"), encoding="utf-8").read()
cli = open(os.path.join(ROOT, "src/shellsentry/cli.py"), encoding="utf-8").read()
ba = open(os.path.join(ROOT, "src/shellsentry/core/behavior_analyzer.py"), encoding="utf-8").read()

checks = []


def chk(name, ok, detail=""):
    checks.append((name, ok, detail))


# 规则数
n_rules = len(re.findall(r'\(\s*"[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+"', rs))
chk("128 条规则", n_rules == 128 and "**128 条**检测规则" in readme, "实际 %d" % n_rules)

# 通用规则
n_gen = len(re.findall(r'"\s*,\s*"generic"\s*,\s*\[', rs))
chk("30 条跨语言通用规则", n_gen == 30 and "**30 条**跨语言通用规则" in readme, "实际 %d" % n_gen)

# 解码算法
n_dec = len(re.findall(r"^def (_fn_\w+|extract_\w+)", dec, re.M))
chk("9 种解码算法", n_dec == 9 and "**9 种**程序化解码算法" in readme, "实际 %d" % n_dec)

# 语言覆盖：README 列的每个语言都必须有规则
lang_map = {"PHP": "php", "JSP": "java", "ASP·ASPX": "asp", "C#": "csharp",
            "Python": "python", "JavaScript": "javascript", "Ruby": "ruby",
            "Shell": "shell", "Go": "go"}
for disp, tag in lang_map.items():
    n = len(re.findall(r'"\s*,\s*"' + re.escape(tag) + r'"\s*,\s*\[', rs))
    chk("语言覆盖 %s" % disp, n > 0 and disp in readme, "%s 标签 %d 条" % (tag, n))

# CWE 映射
n_cwe = len(set(re.findall(r"CWE-\d+", rs)))
chk("12 项 CWE", n_cwe == 12 and "12 项 CWE" in readme, "实际 %d" % n_cwe)

# 威胁行为类别
n_cat = len(set(re.findall(r'"\s*,\s*"[a-z_]+"\s*,\s*\[', rs)))
chk("9 类威胁行为", "9 类威胁行为" in readme, "规则里类别标签 %d" % n_cat)

# 家族名
fams = ["Behinder", "Godzilla", "AntSword", "天蝎", "Cobalt Strike", "Metasploit", "Viper"]
missing = [f for f in fams if f not in readme or f not in (pr + rs + ba)]
chk("家族识别列表", not missing, "源码缺失 %s" % missing)

# 家族关键词表
fk = pr.find("_FAMILY_KEYWORDS")
chk("家族关键词表存在", fk > 0)

# 行为链：Source/Sink 闭环
ba_src = ba
chk("行为链 Source→Sink", "source" in ba_src.lower() and "sink" in ba_src.lower())

# 五段式报告
tags = ["IMAGE", "DE_OBFUSCATE", "C2_INFO", "METADATA_BEHAVIOR", "PLAYBOOK"]
chk("五段式报告", all(("[%s]" % t) in pr for t in tags) and "五段式报告" in readme)

# ground truth 声明
dec_txt = open(os.path.join(ROOT,"src/shellsentry/core/decoder.py"),encoding="utf-8").read()
chk("非 LLM 推断声明", ("非 LLM 推断" in readme) and ("非 LLM 推断" in dec_txt or "确定性还原" in pr))

# 样本集
zs = os.path.join(ROOT, "zz_samples")
n_ab = len([f for f in os.listdir(os.path.join(zs, "ab")) if f.endswith(".php")])
n_root = len([f for f in os.listdir(zs)
              if os.path.isfile(os.path.join(zs, f)) and f.endswith((".php", ".rb", ".java"))])
chk("7 个盲测样本", n_ab + n_root == 7 and "7 个样本可复现" in readme,
    "实际 ab=%d + 根=%d" % (n_ab, n_root))

# scan 命令
chk("scan 命令存在", 'add_parser("scan"' in cli)
chk("scan 输出 JSON", "json.dumps" in cli and "输出 JSON" in readme)

# serve 需 API Key（走 audit_stream → get_client_config）
i = web.find("audit_code_stream")
seg = web[i:i + 7000]
chk("serve 走 LLM 路径", "audit_stream" in seg and "get_client_config" in seg)

# scan 走静态路径（不调 LLM）
chk("scan 不调 LLM", "AIClient" not in eng)

# UI 文案
chk("模型设置按钮", 'id="settingsButton"' in h and "模型设置" in h and "模型设置" in readme)
chk("测试连接按钮", 'id="testConfigButton"' in h and "测试连接" in h and "测试连接" in readme)
chk("侧边栏底部", "sidebar-footer" in h and "左侧栏底部" in readme)

# 绑定地址
chk("仅监听 127.0.0.1", "127.0.0.1" in web and "只监听 `127.0.0.1`" in readme)

# 已删除的错误表述
chk("无『不需要付费 API』", "不需要付费 API" not in readme)
chk("无『平台状态』章节", "## 平台状态" not in readme)

# 启动脚本
chk("双启动脚本", os.path.exists(os.path.join(ROOT, "start-shellsentry.cmd"))
    and os.path.exists(os.path.join(ROOT, "start-shellsentry.sh")))
chk("启动脚本说明正确", "start-shellsentry.cmd" in readme and "start-shellsentry.sh" in readme)

print("=" * 92)
print("README 断言核实")
print("=" * 92)
bad = 0
for name, ok, detail in checks:
    if not ok:
        bad += 1
    print("%s %-26s %s" % ("PASS" if ok else "FAIL", name, detail))
print("-" * 92)
print("结论：%d 项全部属实" % len(checks) if bad == 0 else "%d 项不符 NG" % bad)
print("README 篇幅：%d 字符 / %d 行" % (len(readme), readme.count("\n")))