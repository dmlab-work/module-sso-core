<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Mapping;

/**
 * Resolves IdP group/claim values into target keys via configurable rules.
 *
 * A rule set is a `source value => target key` map (e.g. an Okta group name to
 * a Magento role id). The engine is stateless — the consuming product owns the
 * rules and passes them in per call.
 */
class MappingEngine
{
    /**
     * Map a set of IdP source values to their target keys.
     *
     * Targets are returned in rule order (the order the rules are configured), not the
     * order the IdP lists its values, so `[0]` is the highest-priority matching rule.
     * Results are de-duplicated. When nothing matches, `$default` is returned as a
     * single-element list, or an empty list when no default is supplied.
     *
     * @param string[] $sourceValues values emitted by the IdP (e.g. group names)
     * @param array<string,string> $rules source value => target key, in priority order
     * @param string|null $default fallback target key when no rule matches
     * @return string[] resolved target keys
     */
    public function resolve(array $sourceValues, array $rules, ?string $default = null): array
    {
        $present = array_fill_keys(array_map('strval', $sourceValues), true);

        $targets = [];
        $seen = [];
        foreach ($rules as $source => $target) {
            // PHP casts numeric-string keys to int; compare as strings.
            if (!isset($present[(string)$source])) {
                continue;
            }
            // Index the seen-set by value, but push the original string target so
            // numeric-like ids (e.g. Magento role "5") keep their string type.
            if (!isset($seen[$target])) {
                $seen[$target] = true;
                $targets[] = $target;
            }
        }

        if ($targets === []) {
            return $default === null ? [] : [$default];
        }

        return $targets;
    }
}
