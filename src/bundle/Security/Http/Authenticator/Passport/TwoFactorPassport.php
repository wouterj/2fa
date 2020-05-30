<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\Http\Authenticator\Passport;

use Scheb\TwoFactorBundle\Security\Authentication\Exception\InvalidTwoFactorCodeException;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

class TwoFactorPassport implements PassportInterface
{
    /**
     * @var TwoFactorTokenInterface
     */
    private $twoFactorToken;

    /**
     * @var BadgeInterface[]
     */
    private $badges = [];

    public function __construct(TwoFactorTokenInterface $twoFactorToken, CredentialsInterface $credentials, array $badges)
    {
        $this->twoFactorToken = $twoFactorToken;
        $this->addBadge($credentials);
        foreach ($badges as $badge) {
            $this->addBadge($badge);
        }
    }

    public function getTwoFactorToken(): TwoFactorTokenInterface
    {
        return $this->twoFactorToken;
    }

    public function addBadge(BadgeInterface $badge): PassportInterface
    {
        $this->badges[\get_class($badge)] = $badge;

        return $this;
    }

    public function hasBadge(string $badgeFqcn): bool
    {
        return isset($this->badges[$badgeFqcn]);
    }

    public function getBadge(string $badgeFqcn): ?BadgeInterface
    {
        return $this->badges[$badgeFqcn] ?? null;
    }

    public function checkIfCompletelyResolved(): void
    {
        foreach ($this->badges as $badge) {
            if (!$badge->isResolved()) {
                throw new InvalidTwoFactorCodeException('Invalid two-factor authentication code.');
            }
        }
    }
}
