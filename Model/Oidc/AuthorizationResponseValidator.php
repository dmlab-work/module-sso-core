<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Api\Data\AuthorizationStateInterface;
use DmLab\SsoCore\Exception\AuthorizationResponseException;

/**
 * Validates the authorization response on the callback before the code is redeemed:
 * mix-up defense (RFC 9700 §4.4) and the RFC 9207 `iss` response parameter.
 */
class AuthorizationResponseValidator
{
    /**
     * Assert the callback belongs to the IdP the request was sent to.
     *
     * The stored state issuer (when known) must equal the discovered issuer; a present
     * `iss` param must equal it too, and is required when the IdP advertises
     * `authorization_response_iss_parameter_supported`.
     *
     * @param string|null $iss the callback's `iss` query param; null when absent
     * @param AuthorizationStateInterface $state consumed one-time state
     * @param ProviderMetadata $metadata provider metadata discovered on the callback
     * @throws AuthorizationResponseException
     */
    public function validateIssuer(?string $iss, AuthorizationStateInterface $state, ProviderMetadata $metadata): void
    {
        $expected = $metadata->getIssuer();

        $stateIssuer = $state->getIssuer();
        if ($stateIssuer !== '' && $stateIssuer !== $expected) {
            throw new AuthorizationResponseException(sprintf(
                'The sign-in was started with issuer "%s" but the provider is now "%s".',
                $stateIssuer,
                $expected
            ));
        }

        if ($iss === null) {
            if ($metadata->isAuthorizationResponseIssParameterSupported()) {
                throw new AuthorizationResponseException('The authorization response is missing the "iss" parameter.');
            }

            return;
        }

        if ($iss !== $expected) {
            throw new AuthorizationResponseException(sprintf(
                'The authorization response "iss" "%s" does not match the expected issuer "%s".',
                $iss,
                $expected
            ));
        }
    }
}
