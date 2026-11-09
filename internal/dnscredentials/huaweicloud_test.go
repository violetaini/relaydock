package dnscredentials

import (
	"errors"
	"testing"
)

func TestNormalizeHuaweiCloud(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]string
		wantAK    string
		wantSK    string
		wantReg   string
		expectErr bool
	}{
		{
			name: "standard lego keys",
			input: map[string]string{
				"HUAWEICLOUD_ACCESS_KEY_ID":     "my-ak",
				"HUAWEICLOUD_SECRET_ACCESS_KEY": "my-sk",
				"HUAWEICLOUD_REGION":            "ap-southeast-1",
			},
			wantAK:  "my-ak",
			wantSK:  "my-sk",
			wantReg: "ap-southeast-1",
		},
		{
			name: "dnsmgr style keys with default region",
			input: map[string]string{
				"AccessKeyId":     "test-ak",
				"SecretAccessKey": "test-sk",
			},
			wantAK:  "test-ak",
			wantSK:  "test-sk",
			wantReg: "cn-north-4",
		},
		{
			name: "short keys ak sk",
			input: map[string]string{
				"ak":     "ak123",
				"sk":     "sk456",
				"region": "cn-east-3",
			},
			wantAK:  "ak123",
			wantSK:  "sk456",
			wantReg: "cn-east-3",
		},
		{
			name: "missing sk",
			input: map[string]string{
				"ak": "ak123",
			},
			expectErr: true,
		},
		{
			name: "missing ak",
			input: map[string]string{
				"sk": "sk456",
			},
			expectErr: true,
		},
		{
			name:      "empty credentials",
			input:     map[string]string{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeHuaweiCloud(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got[HuaweiCloudAccessKeyIDKey] != tt.wantAK {
				t.Errorf("AK = %q, want %q", got[HuaweiCloudAccessKeyIDKey], tt.wantAK)
			}
			if got[HuaweiCloudSecretAccessKeyKey] != tt.wantSK {
				t.Errorf("SK = %q, want %q", got[HuaweiCloudSecretAccessKeyKey], tt.wantSK)
			}
			if got[HuaweiCloudRegionKey] != tt.wantReg {
				t.Errorf("Region = %q, want %q", got[HuaweiCloudRegionKey], tt.wantReg)
			}
		})
	}
}

func TestFriendlyHuaweiCloudError(t *testing.T) {
	orig := errors.New("request failed: auth signature mismatch for accesskey")
	friendly := FriendlyHuaweiCloudError(orig)
	if friendly == orig {
		t.Errorf("expected error to be wrapped with friendly advice")
	}
}
