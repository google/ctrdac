// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package lookup features some helper functions to extract data from deeply nested structures.
package lookup

import (
	"errors"
	"fmt"
	"strings"
)

// Lookup is a helper function to extract a value from a map at the given path.
// If the path is not found, it returns the default value.
func Lookup[T any](srcMap any, path string, defValue T) T {
	src, ok := srcMap.(map[string]any)
	if !ok {
		return defValue
	}
	ss := strings.SplitN(path, ".", 2)
	key := ss[0]
	av := src[key]
	if av == nil {
		return defValue
	}

	if len(ss) > 1 {
		return Lookup(av, ss[1], defValue)
	}

	re, ok := av.(T)
	if !ok {
		return defValue
	}
	return re
}

// ToStrSlice is a helper function to convert an any slice into a string slice.
func ToStrSlice(src []any) ([]string, error) {
	var re []string
	for _, m := range src {
		ms, ok := m.(string)
		if !ok {
			return nil, fmt.Errorf("unable to convert process.args: %v is not a string", ms)
		}
		re = append(re, ms)
	}
	return re, nil
}

// Patch sets a new value in dstMap at path
func Patch(dstMap any, path string, newValue any) error {
	dst, ok := dstMap.(map[string]any)
	if !ok {
		return errors.New("dst is not a map")
	}
	ss := strings.SplitN(path, ".", 2)

	if len(ss) > 1 {
		key := ss[0]
		av := dst[key]
		if av == nil {
			return fmt.Errorf("dst does not contain %s", key)
		}

		return Patch(av, ss[1], newValue)
	}

	// this is the last
	dst[path] = newValue
	return nil
}
