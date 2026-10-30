<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit;

use PHPUnit\Framework\TestCase;

class PackagingTest extends TestCase
{
    private const REPO = 'https://github.com/dmlab-work/module-sso-core';

    /**
     * @return array<string, mixed>
     */
    private function composer(): array
    {
        $composer = json_decode((string)file_get_contents(dirname(__DIR__, 2) . '/composer.json'), true);
        self::assertIsArray($composer);

        return $composer;
    }

    private function ciWorkflow(): string
    {
        return (string)file_get_contents(dirname(__DIR__, 2) . '/.github/workflows/ci.yml');
    }

    public function testRequireCoversMagento247AndPhp82(): void
    {
        self::assertSame(
            [
                'php' => '~8.2.0||~8.3.0||~8.4.0||~8.5.0',
                'ext-curl' => '*',
                'magento/framework' => '^103.0.7',
                'web-token/jwt-framework' => '^3.4.10||~4.0.7||^4.1.7',
            ],
            $this->composer()['require']
        );
    }

    public function testRequireDevAcceptsPhpunit11And12(): void
    {
        self::assertSame(['phpunit/phpunit' => '^11.5||^12.5'], $this->composer()['require-dev']);
    }

    public function testHomepageAndSupportLinks(): void
    {
        $composer = $this->composer();

        self::assertSame(self::REPO, $composer['homepage']);
        self::assertSame(
            ['issues' => self::REPO . '/issues', 'source' => self::REPO],
            $composer['support']
        );
    }

    public function testKeywords(): void
    {
        $keywords = $this->composer()['keywords'];

        self::assertContains('magento2', $keywords);
        self::assertContains('oidc', $keywords);
    }

    public function testCiMatrixCoversPhp82To85(): void
    {
        self::assertStringContainsString("php: ['8.2', '8.3', '8.4', '8.5']", $this->ciWorkflow());
    }

    public function testCiDisablesPackagistNotifyBeforeInstall(): void
    {
        $ci = $this->ciWorkflow();
        $notify = strpos($ci, 'composer config notify-on-install false');
        $install = strpos($ci, 'ramsey/composer-install');

        self::assertNotFalse($notify);
        self::assertNotFalse($install);
        self::assertLessThan($install, $notify);
    }

    public function testReadmeRequirementsLine(): void
    {
        self::assertStringContainsString('Magento 2.4.7+ · PHP 8.2–8.5', $this->readme());
    }

    public function testReadmeScreenshotExists(): void
    {
        $image = '.github/images/admin-sso-config.png';

        self::assertStringContainsString('](' . $image . ')', $this->readme());
        self::assertFileExists(dirname(__DIR__, 2) . '/' . $image);
    }

    public function testVersion(): void
    {
        self::assertSame('0.2.4', $this->composer()['version']);
    }

    public function testChangelogStartsWithCurrentVersion(): void
    {
        $changelog = (string)file_get_contents(dirname(__DIR__, 2) . '/CHANGELOG.md');

        self::assertSame(1, preg_match('/^## (\S+)/m', $changelog, $match));
        self::assertSame('0.2.4', $match[1]);
    }

    private function readme(): string
    {
        return (string)file_get_contents(dirname(__DIR__, 2) . '/README.md');
    }
}
