"""ShellSentry-AI 修复验证（走完整 HTTP 链路，与用户 UI 完全一致）

为什么必须走 HTTP、而不是自建脚本直接调 audit_stream：
  2026-10-07 的教训 —— 上一轮用自建脚本验证"P0 行号问题已修复"，
  但脚本只覆盖了分片阶段、漏掉综合阶段，于是结论是错的：
  用户走 UI 重跑后，综合报告里仍出现 L66/L396/L482 等物理上不存在的行号。
  工具的"分片 → 综合"两条路径必须一起验证。

用法：
  1) 起一个独立实例（不必动你正在用的端口）：
     .venv/Scripts/python.exe -m uvicorn shellsentry.web.app:app --port 8791
  2) 跑验证：
     .venv/Scripts/python.exe tools/verify_fix_http.py http://127.0.0.1:8791

退出码：0 = 全部通过；1 = 有未通过项。
"""
import json
import re
import os
import sys
import time
import urllib.request
import uuid

# 允许直接从 tools/ 目录运行：需要 import shellsentry 以计算规范化后行数
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8791'
# 样本路径基于本文件位置推导，不写死绝对路径 ——
# 否则 clone 到别的机器/目录就跑不起来（开源前必修项）。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = [
    # (样本, 期望 verdict, 原始物理行数, 是否原始单行)
    (os.path.join(ROOT, 'zz_samples', 'ab', 'ab_bench_php_single_line_huge.php'), 'malicious', 1, True),
    (os.path.join(ROOT, 'zz_samples', 'ab', 'ab_bench_php_tail_backdoor.php'), 'malicious', 529, False),
    (os.path.join(ROOT, 'zz_samples', 'ab', 'ab_bench_php_clean_control.php'), 'benign', 527, False),
    (os.path.join(ROOT, 'zz_samples', 'ab', 'ab_bench_php_single_line_small.php'), 'malicious', 1, True),
    (os.path.join(ROOT, 'zz_samples', 'bx_php.php'), 'malicious', 21, False),
    (os.path.join(ROOT, 'zz_samples', 'reverse_shell.rb'), 'malicious', 5, False),
    (os.path.join(ROOT, 'zz_samples', 'AesUtil.java'), 'benign', 19, False),
]


def post_stream(path, content, filename, timeout=1800):
    """multipart 上传并消费 SSE —— 与前端 fetch 调用等价。"""
    boundary = '----shellsentry' + uuid.uuid4().hex
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: application/octet-stream\r\n\r\n'
    ).encode('utf-8') + content.encode('utf-8') + f'\r\n--{boundary}--\r\n'.encode('utf-8')

    req = urllib.request.Request(
        f'{BASE}/api/audit/stream', data=body, method='POST',
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    text = ''
    done = {}
    events = {}
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        buf = ''
        while True:
            chunk = resp.read(4096)
            if not chunk:
                break
            buf += chunk.decode('utf-8', 'replace')
            while '\n\n' in buf:
                block, buf = buf.split('\n\n', 1)
                for line in block.splitlines():
                    if line.startswith('event: '):
                        nm = line[7:].strip()
                        events[nm] = events.get(nm, 0) + 1
                    elif line.startswith('data: '):
                        try:
                            obj = json.loads(line[6:])
                        except Exception:
                            continue
                        if 'text' in obj:
                            text += obj['text']
                        elif 'verdict' in obj or 'success' in obj:
                            done = obj
    return text, done, events


def latest_record(basename, after_ts=''):
    """读取服务端落盘的最新历史记录 —— UI 展示的就是这份。

    after_ts 必须传入本次请求开始前的时间戳：只按文件名取最新会**假通过** ——
    若新记录未落盘成功，会读到上一轮（已知有问题）的旧记录，从而误判为"已修复"。
    这里强制要求记录时间晚于本次请求开始，杜绝这种假阳性。
    """
    import glob
    import os
    d = os.path.expandvars(r'%LOCALAPPDATA%\ShellSentry\history')
    fs = sorted(glob.glob(os.path.join(d, '*.json')), key=os.path.getmtime)
    for f in reversed(fs):
        j = json.load(open(f, encoding='utf-8'))
        if j.get('filename') != basename:
            continue
        ts = (j.get('timestamp') or '')[:19]
        if after_ts and ts <= after_ts:
            return None  # 只有旧记录 → 本轮未落盘，不能拿来当证据
        return j
    return None


def check(name, ok, detail=''):
    print('   %s %s%s' % ('PASS' if ok else 'FAIL', name, '' if ok else f'  ← {detail}'))
    return ok


def main():
    all_ok = True
    for path, expect_verdict, nlines, single in SAMPLES:
        code = open(path, encoding='utf-8').read()
        fname = path.replace('\\', '/').split('/')[-1]
        print('=' * 92)
        print('样本 %s | 物理 %d 行 | 期望 %s' % (fname, nlines, expect_verdict))
        print('-' * 92)
        t0 = time.time()
        # 本次请求开始时刻（ISO 秒级），用于强制校验落盘记录来自本轮
        start_iso = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t0))
        text, done, events = post_stream('/api/audit/stream', code, fname)
        dt = time.time() - t0
        print('   耗时 %.1fs | SSE %s | 文本 %d 字符' % (dt, events, len(text)))
        print('   本轮起始时刻 %s（落盘记录必须晚于此）' % start_iso)

        # 1) 四模块完整性
        for tag in ('IMAGE', 'DE_OBFUSCATE', 'METADATA_BEHAVIOR', 'PLAYBOOK'):
            body = re.search(r'\[%s\](.*?)\[/%s\]' % (tag, tag), text, re.S)
            all_ok &= check(f'模块 {tag} 闭合且非空',
                            bool(body) and len(body.group(1).strip()) > 40,
                            '缺失或过短')

        # 2) 行号越界。
        #    ⚠ 判定基准必须是**规范化后**的代码行数，不是原始文件行数。
        #    2026-10-08 的教训：服务端 pre_format_malware_code 会把单行压缩代码
        #    重排成多行（实测 ab_bench_php_single_line_huge.php：1 行 → 701 行），
        #    引擎与模型面对的都是规范化后的代码。此前用原始 1 行做基准，
        #    把模型对规范化代码的**真实行号引用**误判成"编造行号"，导致误报。
        from shellsentry.core.input_handler import pre_format_malware_code
        norm = pre_format_malware_code(code, fname)
        eff_lines = len(norm.splitlines())
        refs = sorted({int(x) for x in re.findall(r'L(\d+)', text)})
        bad = [r for r in refs if r > eff_lines]
        all_ok &= check(
            '行号在规范化代码范围内', not bad,
            f'越界行号={bad}；原始 {nlines} 行，规范化后 {eff_lines} 行')

        # 3) 结论正确
        got = (done.get('verdict') or '').lower()
        all_ok &= check(f'结论 = {expect_verdict}', got == expect_verdict, f'实际 {got}')

        # 4) family 不得凭空断言
        fam = (done.get('attack_profile') or {}).get('family', '')
        if single:
            all_ok &= check('family 未凭空断言（单行样本模型自认未知→应为空）',
                            fam != 'Behinder', f'实际 {fam!r}')

        # 5) 服务端落盘记录与流一致（必须是本轮的新记录，不接受旧记录）
        rec = latest_record(fname, after_ts=start_iso)
        all_ok &= check('本轮有新的落盘记录', rec is not None,
                        '未找到晚于本轮起始时刻的记录 → 无法验证落盘链路（不可用旧记录顶替）')
        if rec:
            rraw = (rec.get('report') or {}).get('raw_ai_output') or ''
            rrefs = sorted({int(x) for x in re.findall(r'L(\d+)', rraw)})
            rbad = [r for r in rrefs if r > eff_lines]
            all_ok &= check('落盘记录行号同样在范围内', not rbad,
                            f'越界={rbad}；规范化后共 {eff_lines} 行')
            rdone = (rec.get('report') or {}).get('done') or {}
            all_ok &= check('落盘记录 non-empty/non-truncated',
                            not rdone.get('empty_output') and not rdone.get('report_truncated'),
                            str({k: rdone.get(k) for k in ('empty_output', 'report_truncated')}))
            print('   落盘 family=%r verdict=%s @%s' % (
                (rdone.get('attack_profile') or {}).get('family'),
                rdone.get('verdict'), (rec.get('timestamp') or '')[11:19]))
        print()
    print('=' * 92)
    print('总判定:', 'ALL PASS' if all_ok else '*** 存在未通过项***')
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())