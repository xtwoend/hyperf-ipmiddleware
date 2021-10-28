<?php

namespace Growinc\IpMiddleware;

use Psr\Http\Server\MiddlewareInterface;


class WhitelistMiddleware extends Middleware implements MiddlewareInterface
{
    public function process(
        RequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $whitelist = config('ip-middleware.whitelist');
        
        if ($this->shouldCheck() 
            && ! in_array(
                $this->determineClientIpAddress($request), 
                $this->parsePredefinedListItem($whitelist))
        ) {
            $this->abort();
        }


        return $handler->handle($request);
    }
}