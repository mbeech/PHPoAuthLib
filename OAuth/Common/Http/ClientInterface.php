<?php
/**
 * @author Lusitanian <alusitanian@gmail.com>
 * Released under the MIT license.
 */

namespace OAuth\Common\Http;
use OAuth\Common\Http\Exception\TokenResponseException;

interface ClientInterface
{
    /**
     * Any implementing HTTP providers should send a POST request to the provided endpoint with the parameters.
     * They should return, in string form, the response body and throw an exception on error.
     *
     * @abstract
     * @param string $endpoint
     * @param array $params
     * @param array $extraHeaders
     * @return string
     * @throws TokenResponseException
     */
    public function retrieveResponse($endpoint, array $params, array $extraHeaders = []);
}