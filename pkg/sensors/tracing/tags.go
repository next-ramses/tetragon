// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
)

const (
	// Max tags of a Tracing Policy
	TpMaxTags   = 16
	TpMinTagLen = 2
	TpMaxTagLen = 128
)

var (
	ErrTagsSyntaxLong  = errors.New("tags field: too many tags")
	ErrTagSyntaxShort  = errors.New("too short")
	ErrTagSyntaxEscape = errors.New("escape failed")
)

func escapeTag(tag string) (string, error) {
	l := len(tag)
	if l < TpMinTagLen {
		return "", ErrTagSyntaxShort
	} else if l > TpMaxTagLen {
		l = TpMaxTagLen
	}

	t := fmt.Sprintf("%q", tag[:l])
	newLen := len(t)
	if newLen <= l || t[0] != '"' || t[newLen-1] != '"' {
		return "", ErrTagSyntaxEscape
	}

	// Remove double quoted string so we pretty print it later in the events
	return t[1 : newLen-1], nil
}

// Default tags
var defaultTags = map[string]bool{
	"observability.filesystem": true,
	"observability.privilege":  true,
	"observability.process":    true,
}

// getPolicyTags() Validates and escapes the passed tags.
// Returns: On success the validated tags of max length TpMaxTags
// On failures an error is set.
func getPolicyTags(tags []string) ([]string, error) {
	l := len(tags)
	if l == 0 {
		return tags, nil
	} else if l > TpMaxTags {
		return nil, ErrTagsSyntaxLong
	}

	var newTags []string
	for i, v := range tags {
		_, ok := defaultTags[v]
		if !ok {
			parsed, err := escapeTag(v)
			if err != nil {
				return nil, fmt.Errorf("custom tag n%d: %v", i, err)
			}
			v = parsed
		}
		newTags = append(newTags, v)
	}

	return newTags, nil
}
