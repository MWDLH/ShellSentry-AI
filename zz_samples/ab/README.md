# A/B 盲测样本集

本目录是 ShellSentry-AI 内置的**盲测样本集**，用来验证端到端检测能力 ——
尤其是「样本再长，分析也要覆盖到文件后半部分的恶意逻辑」，而不是只读开头就下结论。

样本都是**自造的合成代码**，不含任何真实攻击者基础设施：所有回连地址均为保留/私有地址
（例如 `127.0.0.1:8443`）。它们仅作为静态审计对象，工具在任何情况下都不会执行它们。

重新生成：

```bash
python tools/gen_ab_samples.py
```

---

## 样本清单

| 文件 | 行数 | 说明 |
|---|---|---|
| `ab_bench_php_tail_backdoor.php` | 530 | **主样本**：后门逻辑整体位于文件后半段（第 284 行之后） |
| `ab_bench_php_clean_control.php` | 528 | **良性对照**：体量与主样本相近、无恶意代码，用于检查是否误报 |
| `ab_bench_php_single_line_small.php` | 1 | 单行样本：整份代码压成一行 |
| `ab_bench_php_single_line_huge.php` | 1 | 超长单行样本：用于验证超长单行的分段处理 |

---

## 参考判定

> 本节直接给出样本的正确答案。若你想先自行审计、再把结果当作对照，
> 请跳过本节，跑完后再回来看。

### 主样本 `ab_bench_php_tail_backdoor.php` —— malicious

前半部分是正常的「模板缓存编译器」（`TemplateCacheCompiler`）外观，后半段藏了一条
外部输入 → 解码还原 → 动态执行的完整攻击链：

```
$_POST[$slot] / $_COOKIE[$slot]        ← 外部输入
        │
        ├─ inbound()       L380   读取请求参数
        ├─ unpack()        L396   URL-safe base64 解码
        ├─ unlock()        L408   按会话密钥逐字节异或还原
        │    └─ negotiateKey()  L363   密钥由 HTTP_HOST + __FILE__ 派生
        └─ eval($source)   L433   还原结果直接交给 PHP 执行
```

第二落点 `DiagnosticsRunner`（伪装成只读运维自检）：

- `probe()` L471：声称有白名单，未命中时回退到 `$_REQUEST['args']` → `shell_exec()`
- `snapshot()` L479：把 `php://input` 原始流写入临时目录（落地通道）
- `beacon()` L493：`fsockopen()` 主动回连探测（占位 `127.0.0.1:8443`）

入口 `RuntimeBootstrap::register()` L529 在文件末尾无条件执行。

| 维度 | 期望值 |
|---|---|
| 结论 | malicious |
| 攻击意图 | 加密信道下的远程代码执行 WebShell |
| 关键行为 | 会话密钥协商 / base64+XOR 双层还原 / eval / shell_exec / php://input 落地 |
| C2 资产 | `127.0.0.1:8443`（占位地址，非真实外联） |

攻击链上的关键动作（L363 / L380 / L396 / L408 / L433 / L471 / L479 / L493 / L529）
都应出现在报告的 `[METADATA_BEHAVIOR]` 面板里 —— 这正是「后半段也被读到」的证据。

### 良性对照 `ab_bench_php_clean_control.php` —— benign

应判为 clean / benign。若被判为恶意，或 `[C2_INFO]`、`[METADATA_BEHAVIOR]`
里出现具体指控，说明出现了误报，需要复核。

### 单行样本 —— malicious

`ab_bench_php_single_line_small.php` 与 `ab_bench_php_single_line_huge.php`
均含与主样本同源的恶意逻辑，用于验证单行、超长单行输入下的检测与行号展示是否正确。
