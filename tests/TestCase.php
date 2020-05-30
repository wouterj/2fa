<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Tests;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Symfony\Component\HttpKernel\Kernel;

// phpcs:ignore Symfony.NamingConventions.ValidClassName
abstract class TestCase extends PHPUnitTestCase
{
    private const AUTHENTICATORS_MIN_SYMFONY_VERSION = 50100;

    protected function requireAuthenticatorsSupport()
    {
        if (Kernel::VERSION_ID < self::AUTHENTICATORS_MIN_SYMFONY_VERSION) {
            $this->markTestSkipped("This Symfony version doesn't support authenticators.");
        }
    }
}
