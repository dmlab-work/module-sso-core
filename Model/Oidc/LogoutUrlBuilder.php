<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

/**
 * Builds the OpenID Connect RP-Initiated Logout 1.0 redirect to the IdP's `end_session_endpoint`.
 */
class LogoutUrlBuilder
{
    /**
     * Build the end-session URL; empty/null params are omitted, a query in the endpoint is kept (§2).
     *
     * @param string $endSessionEndpoint discovered `end_session_endpoint`
     * @param string|null $idTokenHint raw ID token from the login (RECOMMENDED)
     * @param string|null $clientId
     * @param string|null $postLogoutRedirectUri must be registered at the IdP
     * @param string|null $state echoed back to the post-logout redirect URI
     * @throws \InvalidArgumentException when the endpoint is not an https URL
     */
    public function build(
        string $endSessionEndpoint,
        ?string $idTokenHint = null,
        ?string $clientId = null,
        ?string $postLogoutRedirectUri = null,
        ?string $state = null
    ): string {
        if (!str_starts_with(strtolower($endSessionEndpoint), 'https://')) {
            throw new \InvalidArgumentException(
                sprintf('OIDC end_session_endpoint must use HTTPS: "%s".', $endSessionEndpoint)
            );
        }

        $params = [
            'id_token_hint' => $idTokenHint,
            'client_id' => $clientId,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'state' => $state,
        ];
        $params = array_filter($params, static fn(?string $value) => $value !== null && $value !== '');
        if ($params === []) {
            return $endSessionEndpoint;
        }

        $separator = str_contains($endSessionEndpoint, '?') ? '&' : '?';

        return $endSessionEndpoint . $separator . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
