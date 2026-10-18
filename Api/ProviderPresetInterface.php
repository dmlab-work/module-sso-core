<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api;

/**
 * IdP-specific preset supplied by a product module to the generic OIDC engine.
 *
 * Okta/Azure/Google are standard OIDC IdPs that differ only by configuration, so
 * the engine stays generic and each product ships a small preset describing its
 * IdP: how to build the discovery URL, which scopes to request, where groups live
 * in the claims, and branding for the login button.
 *
 * Presets are supplied by thin provider plugin modules (e.g. `admin-sso-okta`),
 * which register them into the capability core's PresetRegistry. The core itself
 * holds no registry and no IdP-specific code.
 */
interface ProviderPresetInterface
{
    /**
     * Stable machine code identifying the IdP (e.g. `okta`, `azure`).
     */
    public function getCode(): string;

    /**
     * Human-readable IdP name for the admin UI (e.g. `Okta`).
     */
    public function getLabel(): string;

    /**
     * Build the OIDC discovery URL from the product's resolved config.
     *
     * @param array<string,mixed> $config
     */
    public function buildDiscoveryUrl(array $config): string;

    /**
     * OIDC scopes requested by default (always includes `openid`).
     *
     * @return string[]
     */
    public function getDefaultScopes(): array;

    /**
     * Name of the ID-token/userinfo claim carrying group memberships
     * (e.g. `groups`), or null when the IdP exposes none.
     */
    public function getGroupsClaim(): ?string;

    /**
     * Login-button label for the storefront/admin (e.g. `Sign in with Okta`).
     */
    public function getButtonLabel(): string;

    /**
     * URL of the login-button icon, or null when the product ships none.
     */
    public function getButtonIconUrl(): ?string;
}
