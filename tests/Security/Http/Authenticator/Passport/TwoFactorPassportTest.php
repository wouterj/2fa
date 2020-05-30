<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Tests\Security\Http\Authenticator\Passport;

use PHPUnit\Framework\MockObject\MockObject;
use Scheb\TwoFactorBundle\Security\Authentication\Exception\InvalidTwoFactorCodeException;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\Authenticator\Passport\TwoFactorPassport;
use Scheb\TwoFactorBundle\Tests\TestCase;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

class TwoFactorPassportTest extends TestCase
{
    /**
     * @var MockObject|CredentialsInterface
     */
    private $credentials;

    /**
     * @var MockObject|BadgeInterface
     */
    private $badge;

    /**
     * @var TwoFactorPassport
     */
    private $passport;

    protected function setUp(): void
    {
        $this->requireAuthenticatorsSupport();

        $this->credentials = $this->createMock(CredentialsInterface::class);
        $this->badge = $this->createMock(BadgeInterface::class);

        $this->passport = new TwoFactorPassport(
            $this->createMock(TwoFactorTokenInterface::class),
            $this->credentials,
            [$this->badge]
        );
    }

    /**
     * @test
     */
    public function hasBadge_badgeExists_returnTrue(): void
    {
        $badge = $this->createMock(BadgeInterface::class);
        $this->passport->addBadge($badge);

        $this->assertTrue($this->passport->hasBadge(\get_class($this->credentials)));
        $this->assertTrue($this->passport->hasBadge(\get_class($this->badge)));
        $this->assertTrue($this->passport->hasBadge(\get_class($badge)));
    }

    /**
     * @test
     */
    public function hasBadge_badgeNotExists_returnFalse(): void
    {
        $this->assertFalse($this->passport->hasBadge('unknownBadge'));
    }

    /**
     * @test
     */
    public function getBadge_badgeExists_returnThatBadge(): void
    {
        $badge = $this->createMock(BadgeInterface::class);
        $this->passport->addBadge($badge);

        $returnValue = $this->passport->getBadge(\get_class($badge));
        $this->assertSame($badge, $returnValue);
    }

    /**
     * @test
     */
    public function getBadge_badgeNotExists_returnNull(): void
    {
        $returnValue = $this->passport->getBadge('unknownBadge');
        $this->assertNull($returnValue);
    }

    /**
     * @test
     */
    public function checkIfCompletelyResolved_hasUnresolvedBadges_throwInvalidTwoFactorCodeException(): void
    {
        $this->badge
            ->expects($this->any())
            ->method('isResolved')
            ->willReturn(true);

        $this->credentials
            ->expects($this->any())
            ->method('isResolved')
            ->willReturn(false);

        $this->expectException(InvalidTwoFactorCodeException::class);
        $this->passport->checkIfCompletelyResolved();
    }

    /**
     * @test
     */
    public function checkIfCompletelyResolved_allBadgesResolved_doNothing(): void
    {
        $this->badge
            ->expects($this->once())
            ->method('isResolved')
            ->willReturn(true);

        $this->credentials
            ->expects($this->once())
            ->method('isResolved')
            ->willReturn(true);

        $this->passport->checkIfCompletelyResolved();
    }
}
