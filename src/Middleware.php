<?php

declare(strict_types=1);

namespace Growinc\IpMiddleware;

use Growinc\IpMiddleware\ForbiddenAccessException;

abstract class Middleware
{
    protected $checkProxyHeaders;

    protected $trustedProxies;

    protected $trustedWildcard;

    protected $trustedCidr;

    protected $attributeName = 'ip';

    protected $headersToInspect = [
        'forwarded',
        'x-forwarded-for',
        'x-forwarded',
        'x-cluster-client-ip',
        'client-ip',
        'x-real-ip',
    ];

    public function determineClientIpAddress($request)
    {
        $ipAddress = null;

        $serverParams = $request->getServerParams();

        if (isset($serverParams['remote_addr'])) {
            $remoteAddr = $this->extractIpAddress($serverParams['remote_addr']);
            if ($this->isValidIpAddress($remoteAddr)) {
                $ipAddress = $remoteAddr;
            }
        }

        $checkProxyHeaders = $this->checkProxyHeaders;
        
        if ($checkProxyHeaders) {
            // Exact Match
            if ($this->trustedProxies && ! in_array($ipAddress, $this->trustedProxies)) {
                $checkProxyHeaders = false;
            }
            
            // Wildcard Match
            if ($checkProxyHeaders && $this->trustedWildcard) {
                $checkProxyHeaders = false;
                // IPv4 has 4 parts separated by '.'
                // IPv6 has 8 parts separated by ':'
                if (strpos($ipAddress, '.') > 0) {
                    $delim = '.';
                    $parts = 4;
                } else {
                    $delim = ':';
                    $parts = 8;
                }
                $ipAddrParts = explode($delim, $ipAddress, $parts);
                foreach ($this->trustedWildcard as $proxy) {
                    if (count($proxy) !== $parts) {
                        continue; // IP version does not match
                    }
                    foreach ($proxy as $i => $part) {
                        if ($part !== '*' && $part !== $ipAddrParts[$i]) {
                            break 2; // IP does not match, move to next proxy
                        }
                    }
                    $checkProxyHeaders = true;
                    break;
                }
            }
            
            // CIDR Match
            if ($checkProxyHeaders && $this->trustedCidr) {
                $checkProxyHeaders = false;
                // Only IPv4 is supported for CIDR matching
                $ipAsLong = ip2long($ipAddress);
                if ($ipAsLong) {
                    foreach ($this->trustedCidr as $proxy) {
                        if ($proxy[0] <= $ipAsLong && $ipAsLong <= $proxy[1]) {
                            $checkProxyHeaders = true;
                            break;
                        }
                    }
                }
            }
        }

        if ($checkProxyHeaders) {
            foreach ($this->headersToInspect as $header) {
                if ($request->hasHeader($header)) {
                    $ip = $this->getFirstIpAddressFromHeader($request, $header);
                    if ($this->isValidIpAddress($ip)) {
                        $ipAddress = $ip;
                        break;
                    }
                }
            }
        }

        return $ipAddress;
    }

    /**
     * @param array<string>|string $item
     *
     * @return array<string>
     */
    protected function parsePredefinedListItem($item): array
    {
        if (is_array($item)) {
            return $item;
        }

        return explode(',', $item);
    }

    protected function trustedProxies(array $trustedProxies)
    {
        foreach ($trustedProxies as $proxy) {
            if (strpos($proxy, '*') !== false) {
                // Wildcard IP address
                // IPv6 is 8 parts separated by ':'
                if (strpos($proxy, '.') > 0) {
                    $delim = '.';
                    $parts = 4;
                } else {
                    $delim = ':';
                    $parts = 8;
                }
                $this->trustedWildcard[] = explode($delim, $proxy, $parts);
            } elseif (strpos($proxy, '/') > 6) {
                // CIDR notation
                [$subnet, $bits] = explode('/', $proxy, 2);
                $subnet = ip2long($subnet);
                $mask = -1 << (32 - $bits);
                $min = $subnet & $mask;
                $max = $subnet | ~$mask;
                $this->trustedCidr[] = [$min, $max];
            } else {
                // String-match IP address
                $this->trustedProxies[] = $proxy;
            }
        }
    }

    protected function extractIpAddress($ipAddress)
    {
        $parts = explode(':', $ipAddress);
        if (count($parts) == 2) {
            if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $parts[0];
            }
        }

        return $ipAddress;
    }

    protected function isValidIpAddress($ip)
    {
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
            return false;
        }
        return true;
    }

    private function getFirstIpAddressFromHeader($request, $header)
    {
        $items = explode(',', $request->getHeaderLine($header));
        $headerValue = trim(reset($items));

        if (ucfirst($header) == 'forwarded') {
            foreach (explode(';', $headerValue) as $headerPart) {
                if (strtolower(substr($headerPart, 0, 4)) == 'for=') {
                    $for = explode(']', $headerPart);
                    $headerValue = trim(substr(reset($for), 4), " \t\n\r\0\x0B" . '"[]');
                    break;
                }
            }
        }

        return $this->extractIpAddress($headerValue);
    }

    protected function shouldCheck(): bool
    {
        return config('ip-middleware.bypass', false);
    }

    protected function abort()
    {
        throw new ForbiddenAccessException('Forbidden Access.', 403);
    }
}
