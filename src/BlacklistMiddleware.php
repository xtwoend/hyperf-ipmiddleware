<?php

namespace Growinc\IpMiddleware;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;


class BlacklistMiddleware extends Middleware implements MiddlewareInterface
{
    public function process(
        RequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $blacklist = config('ip-middleware.blacklist');
        
        if ($this->shouldCheck() 
            && in_array(
                $this->determineClientIpAddress($request), 
                $this->parsePredefinedListItem($blacklist))
        ) {
            $this->abort();
        }


        return $handler->handle($request);
    }
}