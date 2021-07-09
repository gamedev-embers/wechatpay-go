package validators

import (
	"context"
	"net/http"

	"github.com/wechatpay-apiv3/wechatpay-go/core/auth"
)

// WechatPayNotifyValidator 微信支付 API v3 通知请求报文验证器
type WechatPayNotifyValidator struct {
	wechatPayValidator
}

// Validate 对接收到的微信支付 API v3 通知请求报文进行验证
func (v *WechatPayNotifyValidator) Validate(ctx context.Context, headers http.Header, body []byte) error {
	return v.validateHTTPMessage(ctx, headers, body)
}

// NewWechatPayNotifyValidator 使用 auth.Verifier 初始化一个 WechatPayNotifyValidator
func NewWechatPayNotifyValidator(verifier auth.Verifier) *WechatPayNotifyValidator {
	return &WechatPayNotifyValidator{
		wechatPayValidator{verifier: verifier},
	}
}
