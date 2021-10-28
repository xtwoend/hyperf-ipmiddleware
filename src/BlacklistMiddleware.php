<?php

namespace Growinc\IpMiddleware;

use Psr\Http\Server\MiddlewareInterface;


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