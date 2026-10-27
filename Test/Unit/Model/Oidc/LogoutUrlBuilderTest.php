<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Model\Oidc\LogoutUrlBuilder;
use PHPUnit\Framework\TestCase;

class LogoutUrlBuilderTest extends TestCase
{
    private const ENDPOINT = 'https://dev.okta.com/oauth2/v1/logout';

    public function testBuildsUrlWithAllParams(): void
    {
        $url = (new LogoutUrlBuilder())->build(
            self::ENDPOINT,
            'id.token+hint',
            'client-123',
            'https://magento.loc/admin/admin/auth/login/',
            'st ate'
        );

        self::assertSame(self::ENDPOINT, strtok($url, '?'));
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame([
            'id_token_hint' => 'id.token+hint',
            'client_id' => 'client-123',
            'post_logout_redirect_uri' => 'https://magento.loc/admin/admin/auth/login/',
            'state' => 'st ate',
        ], $query);
        self::assertStringContainsString('state=st%20ate', $url);
    }

    public function testOmitsEmptyParams(): void
    {
        $builder = new LogoutUrlBuilder();

        self::assertSame(
            self::ENDPOINT . '?id_token_hint=tok',
            $builder->build(self::ENDPOINT, 'tok', '', null)
        );
        self::assertSame(self::ENDPOINT, $builder->build(self::ENDPOINT));
    }

    public function testKeepsEndpointQuery(): void
    {
        $url = (new LogoutUrlBuilder())->build('https://idp.example/logout?tenant=a', 'tok');

        self::assertSame('https://idp.example/logout?tenant=a&id_token_hint=tok', $url);
    }

    public function testRejectsNonHttpsEndpoint(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new LogoutUrlBuilder())->build('http://idp.example/logout', 'tok');
    }
}
