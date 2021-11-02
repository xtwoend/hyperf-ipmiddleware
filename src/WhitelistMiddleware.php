<?php

namespace Growinc\IpMiddleware;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class WhitelistMiddleware extends Middleware implements MiddlewareInterface
{
    public function process(
        RequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $whitelist = config('ip-middleware.whitelist');
        
        if (! $this->shouldCheck() 
            && ! in_array(
                $this->determineClientIpAddress($request), 
                $this->parsePredefinedListItem($whitelist))
        ) {
            $this->abort();
        }


        return $handler->handle($request);
    }
}