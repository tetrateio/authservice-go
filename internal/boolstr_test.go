package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBoolStrValue(t *testing.T) {
	tests := []struct {
		name string
		in   *structpb.Value
		want bool
	}{
		{"empty", &structpb.Value{}, false},
		{"bool", &structpb.Value{Kind: &structpb.Value_BoolValue{BoolValue: true}}, true},
		{"string-true", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "true"}}, true},
		{"string-false", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "false"}}, false},
		{"string-invalid", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "invalid"}}, false},
		{"type-mismatch", &structpb.Value{Kind: &structpb.Value_ListValue{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, BoolStrValue(tt.in))
		})
	}
}
