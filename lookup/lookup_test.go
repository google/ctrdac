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

package lookup

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLookupSimple(t *testing.T) {
	e := "bar"
	m := map[string]any{
		"foo": e,
	}
	a := Lookup(m, "foo", "shouldntbe")
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupAny(t *testing.T) {
	e := "bar"
	m := map[string]any{
		"foo": e,
	}
	var x any = m
	a := Lookup(x, "foo", "shouldntbe")
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupDef(t *testing.T) {
	m := map[string]any{
		"foo": "shouldntbe",
	}
	e := "xx"
	a := Lookup(m, "not-exists", e)
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupDeep(t *testing.T) {
	e := "world"
	m := map[string]any{
		"foo": map[string]any{
			"hello": "world",
		},
	}
	a := Lookup(m, "foo.hello", "shouldntbe")
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupUnexpectedType(t *testing.T) {
	m := map[string]any{
		"foo": true,
	}
	e := "default"
	a := Lookup(m, "foo", "default")
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupNonString(t *testing.T) {
	m := map[string]any{
		"foo": true,
	}
	e := true
	a := Lookup(m, "foo", false)
	if a != e {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestLookupNonPrimitive(t *testing.T) {
	m := map[string]any{
		"foo": []string{"bar", "baz"},
	}
	e := []string{"bar", "baz"}
	a := Lookup(m, "foo", []string{})
	if !reflect.DeepEqual(a, e) {
		t.Errorf("expected: %v, got: %v", e, a)
	}
}

func TestPatchSimple1(t *testing.T) {
	m := map[string]any{
		"foo": "foo-value",
		"bar": map[string]any{
			"baz": "baz-value",
		},
	}
	err := Patch(m, "bar.xxx", "new-value")
	if err != nil {
		t.Fatal(err)
	}
	av := Lookup(m, "bar.xxx", "")
	if av != "new-value" {
		t.Errorf("expected: %v, got: %v", "new-value", av)
	}
}

func TestPatchSimple2(t *testing.T) {
	m := map[string]any{
		"foo": "foo-value",
		"bar": map[string]any{
			"baz": "baz-value",
		},
	}
	err := Patch(m, "bar.baz", "new-baz-value")
	if err != nil {
		t.Fatal(err)
	}
	av := Lookup(m, "bar.baz", "")
	if av != "new-baz-value" {
		t.Errorf("expected: %v, got: %v", "new-baz-value", av)
	}
}

type something struct {
	User any
}

func TestLookupResolvedUcred(t *testing.T) {
	str := `{"User":{"Uid":1234,"Username":"my-username"}}`
	var s something
	err := json.Unmarshal([]byte(str), &s)
	if err != nil {
		t.Fatal(err)
	}

	av := Lookup[float64](s.User, "Uid", 0)
	if av != float64(1234) {
		t.Errorf("expected: %v, got: %v (in %v)", 1234, av, s.User)
	}
}
