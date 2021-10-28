<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */
namespace Growinc\IpMiddleware;


class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for gudang voucher.',
                    'source' => __DIR__ . '/../publish/ip-middleware.php',
                    'destination' => BASE_PATH . '/config/autoload/ip-middleware.php',
                ]
            ],
        ];
    }
}
