package safejson

import "testing"

func TestRejectsDuplicateKeys(t *testing.T) {
	if err := ValidateNoDuplicateKeys([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate key rejection")
	}
	if err := ValidateNoDuplicateKeys([]byte(`{"a":{"b":1,"b":2}}`)); err == nil {
		t.Fatal("expected nested duplicate key rejection")
	}
}

func TestDecodeStrictRejectsUnknown(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	if err := DecodeStrict([]byte(`{"a":1,"extra":2}`), &v); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}
