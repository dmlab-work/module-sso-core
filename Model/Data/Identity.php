<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Data;

use DmLab\SsoCore\Api\Data\IdentityInterface;

/**
 * Immutable value object carrying a normalized identity.
 */
class Identity implements IdentityInterface
{
    /**
     * @var string[]
     */
    private array $groups;

    /**
     * Build the identity value object.
     *
     * @param string $subjectId
     * @param string|null $email
     * @param string|null $name
     * @param string[] $groups
     * @param bool $emailVerified
     * @param string $issuer
     */
    public function __construct(
        private readonly string $subjectId,
        private readonly ?string $email = null,
        private readonly ?string $name = null,
        array $groups = [],
        private readonly bool $emailVerified = false,
        private readonly string $issuer = ''
    ) {
        $this->groups = array_values(array_map('strval', $groups));
    }

    /**
     * Get the subject id.
     */
    public function getSubjectId(): string
    {
        return $this->subjectId;
    }

    /**
     * Get the issuer identifier.
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Get the email address, if present.
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * Whether the email is verified; always false without an email.
     */
    public function isEmailVerified(): bool
    {
        return $this->email !== null && $this->email !== '' && $this->emailVerified;
    }

    /**
     * Get the display name, if present.
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * Get the group memberships.
     *
     * @return string[]
     */
    public function getGroups(): array
    {
        return $this->groups;
    }
}
