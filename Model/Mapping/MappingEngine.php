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
     * Each source value found in `$rules` contributes its target key; results
     * are de-duplicated with first-seen order preserved. When nothing matches,
     * `$default` is returned as a single-element list, or an empty list when no
     * default is supplied.
     *
     * @param string[] $sourceValues values emitted by the IdP (e.g. group names)
     * @param array<string,string> $rules source value => target key
     * @param string|null $default fallback target key when no rule matches
     * @return string[] resolved target keys
     */
    public function resolve(array $sourceValues, array $rules, ?string $default = null): array
    {
        $targets = [];
        $seen = [];
        foreach ($sourceValues as $sourceValue) {
            $key = (string)$sourceValue;
            if (!array_key_exists($key, $rules)) {
                continue;
            }
            // Index the seen-set by value, but push the original string target so
            // numeric-like ids (e.g. Magento role "5") keep their string type.
            $target = $rules[$key];
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
