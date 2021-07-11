package validators

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wechatpay-apiv3/wechatpay-go/core/consts"
)

type mockVerifier struct {
}

func (v *mockVerifier) pack(s string) string {
	return hex.EncodeToString([]byte(s))
}

func (v *mockVerifier) unpack(s string) string {
	rs, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Errorf("%w s=%s", err, s))
	}
	return string(rs)
}

func (v *mockVerifier) Verify(ctx context.Context, serialNumber string, message string, signature string) error {
	signature = v.unpack(signature)
	signActual := serialNumber + "-" + message
	if signActual == signature {
		return nil
	}
	dump := func(s string) string {
		return "\"" + strings.Replace(s, "\n", "\\n", -1) + "\""
	}
	return fmt.Errorf("verification failed: sign(actual=%s expected=%s", dump(signActual), dump(signature))
}

func TestWechatPayResponseValidator_Validate(t *testing.T) {
	mockTimestamp := time.Now().Unix()
	mockTimestampStr := fmt.Sprintf("%d", mockTimestamp)

	verifier := &mockVerifier{}
	validator := NewWechatPayResponseValidator(verifier)

	type args struct {
		ctx      context.Context
		response *http.Response
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "response validate success",
			args: args{
				ctx: context.Background(),
				response: &http.Response{
					Header: http.Header{
						consts.WechatPaySignature: {"SERIAL1234567890-" + mockTimestampStr + "\nNONCE1234567890\nBODY\n"},
						consts.WechatPaySerial:    {"SERIAL1234567890"},
						consts.WechatPayTimestamp: {mockTimestampStr},
						consts.WechatPayNonce:     {"NONCE1234567890"},
						consts.RequestID:          {"any-request-id"},
					},
					Body: ioutil.NopCloser(bytes.NewBuffer([]byte("BODY"))),
				},
			},
			wantErr: false,
		},
		{
			name: "response validate success without body",
			args: args{
				ctx: context.Background(),
				response: &http.Response{
					Header: http.Header{
						consts.WechatPaySignature: {"SERIAL1234567890-" + mockTimestampStr + "\nNONCE1234567890\n\n"},
						consts.WechatPaySerial:    {"SERIAL1234567890"},
						consts.WechatPayTimestamp: {mockTimestampStr},
						consts.WechatPayNonce:     {"NONCE1234567890"},
						consts.RequestID:          {"any-request-id"},
					},
					Body: ioutil.NopCloser(bytes.NewBuffer([]byte(""))),
				},
			},
			wantErr: false,
		},
		{
			name: "response validate verify err",
			args: args{
				ctx: context.Background(),
				response: &http.Response{
					Header: http.Header{
						consts.WechatPaySignature: {"SERIAL1234567890-" + mockTimestampStr + "\nNONCE1234567890\n"},
						consts.WechatPaySerial:    {"SERIAL1234567890"},
						consts.WechatPayTimestamp: {mockTimestampStr},
						consts.WechatPayNonce:     {"NONCE1234567890"},
						consts.RequestID:          {"any-request-id"},
					},
					Body: ioutil.NopCloser(bytes.NewBuffer([]byte(""))),
				},
			},
			wantErr: true,
		},
		{
			name: "response validate decode check parameters err",
			args: args{
				ctx: context.Background(),
				response: &http.Response{
					Header: http.Header{
						consts.WechatPaySignature: {"SERIAL1234567890-" + mockTimestampStr + "\nNONCE1234567890\n"},
						consts.WechatPaySerial:    {"SERIAL1234567890"},
						consts.WechatPayTimestamp: {mockTimestampStr},
						consts.WechatPayNonce:     {"NONCE1234567890"},
					},
					Body: ioutil.NopCloser(bytes.NewBuffer([]byte(""))),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				// 保证 sign 参数中的 "\n" 字符不被 trim 掉（正常情况下不应该有这个字符）
				if sign := tt.args.response.Header.Get(consts.WechatPaySignature); sign != "" {
					tt.args.response.Header.Set(consts.WechatPaySignature, verifier.pack(sign))
				}
				if err := validator.Validate(tt.args.ctx, tt.args.response); (err != nil) != tt.wantErr {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			},
		)
	}
}

func Test_WechatPayNotifyValidator_Validate(t *testing.T) {
	type args struct {
		response *http.Response
	}
	timestampStr := strconv.FormatInt(time.Now().Unix(), 10)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "parameter is valid",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID:          {"1"},
						consts.WechatPaySerial:    {"1"},
						consts.WechatPaySignature: {fmt.Sprintf("1-%s\n1\n\n", timestampStr)},
						consts.WechatPayTimestamp: {timestampStr},
						consts.WechatPayNonce:     {"1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "time is expire",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID:          {"1"},
						consts.WechatPaySerial:    {"1"},
						consts.WechatPaySignature: {"1"},
						consts.WechatPayTimestamp: {"0"},
						consts.WechatPayNonce:     {"1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "nonce is empty",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID:          {"1"},
						consts.WechatPaySerial:    {"1"},
						consts.WechatPaySignature: {"1"},
						consts.WechatPayTimestamp: {strconv.FormatInt(0, 10)},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "timestamp is empty",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID:          {"1"},
						consts.WechatPaySerial:    {"1"},
						consts.WechatPaySignature: {"1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "signature is empty",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID:          {"1"},
						consts.WechatPaySerial:    {"1"},
						consts.WechatPaySignature: {"1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "serial number is empty",
			args: args{
				response: &http.Response{
					Header: map[string][]string{
						consts.RequestID: {"1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "request id is empty",
			args: args{
				response: &http.Response{
					Header: map[string][]string{},
				},
			},
			wantErr: true,
		},
	}
	ctx := context.Background()
	verifier := &mockVerifier{}
	validator := NewWechatPayNotifyValidator(verifier)
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				var (
					body []byte
					err  error
				)
				if tt.args.response.Body != nil {
					body, err = ioutil.ReadAll(tt.args.response.Body)
					require.NoError(t, err)
				}

				// 保证 sign 参数中的 "\n" 字符不被 trim 掉（正常情况下不应该有这个字符）
				if sign := tt.args.response.Header.Get(consts.WechatPaySignature); sign != "" {
					tt.args.response.Header.Set(consts.WechatPaySignature, verifier.pack(sign))
				}

				if err := validator.Validate(ctx, tt.args.response.Header, body); (err != nil) != tt.wantErr {
					t.Errorf("validateParameters() error = %v, wantErr %v", err, tt.wantErr)
				}
			},
		)
	}
}

func TestNullValidator_Validate(t *testing.T) {
	nullValidator := NullValidator{}

	assert.NoError(t, nullValidator.Validate(context.Background(), &http.Response{}))
	assert.NoError(t, nullValidator.Validate(context.Background(), nil))
}
