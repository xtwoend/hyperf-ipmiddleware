<?php

declare(strict_types=1);

namespace Growinc\IpMiddleware;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class IpMiddleware extends Middleware implements MiddlewareInterface
{
    public function __construct(
        $attributeName = null,
        array $headersToInspect = []
    ) {
        $trustedProxies = config('ip-middleware.proxies');
        $trustedProxies = $this->parsePredefinedListItem($trustedProxies);
        $this->checkProxyHeaders = count($trustedProxies) > 0;

        $this->trustedProxies($trustedProxies);
        
        if ($attributeName) {
            $this->attributeName = $attributeName;
        }
        if (! empty($headersToInspect)) {
            $this->headersToInspect = $headersToInspect;
        }
    }

    public function process(
        RequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $ipAddress = $this->determineClientIpAddress($request);
        $request = $request->withAttribute($this->attributeName, $ipAddress);

        return $handler->handle($request);
    }
}
