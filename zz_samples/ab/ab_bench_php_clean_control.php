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

/**
 * 退款工单读取器
 */
final class RefundTicket
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取RefundTicket清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listRefundTicket(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'refunds', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的退款工单', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验RefundTicket在当前阶段是否可流转
     */
    public function canAdvanceRefundTicket(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的退款单阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总RefundTicket金额口径，返回分为单位
     */
    public function sumRefundTicket(array $rows): int
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
 * 库存流水读取器
 */
final class StockLedger
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取StockLedger清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listStockLedger(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'stock_ledger', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的库存流水', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验StockLedger在当前阶段是否可流转
     */
    public function canAdvanceStockLedger(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的库存流水阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总StockLedger金额口径，返回分为单位
     */
    public function sumStockLedger(array $rows): int
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
 * 审计轨迹读取器
 */
final class AuditTrail
{
    private OrderRepositoryInterface $orders;
    private LoggerInterface $logger;

    public function __construct(OrderRepositoryInterface $orders, LoggerInterface $logger)
    {
        $this->orders = $orders;
        $this->logger = $logger;
    }

    /**
     * 读取AuditTrail清单，按创建时间倒序
     *
     * @return array<int, array<string, mixed>>
     */
    public function listAuditTrail(int $tenantId, int $limit = 20): array
    {
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $rows = $this->orders->findByTenant($tenantId, 'audit_trail', $limit);
        foreach ($rows as $idx => $row) {
            $rows[$idx]['created_at'] = date('c', (int) ($row['created_at'] ?? 0));
            $rows[$idx]['stage']      = FulfillmentStage::label((int) ($row['stage'] ?? 0));
            $rows[$idx]['amount']     = number_format((float) ($row['amount'] ?? 0), 2, '.', '');
        }
        $this->logger->debug('已加载指定租户的审计轨迹', ['tenant' => $tenantId, 'count' => count($rows)]);
        return $rows;
    }

    /**
     * 校验AuditTrail在当前阶段是否可流转
     */
    public function canAdvanceAuditTrail(int $current, int $target): bool
    {
        $ok = FulfillmentStage::canTransfer($current, $target);
        if (!$ok) {
            $this->logger->warning('非法的审计轨迹阶段流转', [
                'from' => FulfillmentStage::label($current),
                'to'   => FulfillmentStage::label($target),
            ]);
        }
        return $ok;
    }

    /**
     * 汇总AuditTrail金额口径，返回分为单位
     */
    public function sumAuditTrail(array $rows): int
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
        return implode("\n", $lines);
    }
}

/**
 * 命令行自检入口：仅在 CLI 下执行，Web 请求不会触达。
 */
if (PHP_SAPI === 'cli') {
    $exporter = new SnapshotExporter([]);
    fwrite(STDOUT, $exporter->toJson() . PHP_EOL);
}
