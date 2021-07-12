package validators

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wechatpay-apiv3/wechatpay-go/core/auth"
	"github.com/wechatpay-apiv3/wechatpay-go/core/consts"
)

type wechatPayValidator struct {
	verifier auth.Verifier
}

func (v *wechatPayValidator) validateHTTPMessage(ctx context.Context, header http.Header, body []byte) error {
	requestId := header.Get(consts.RequestID)
	if v.verifier == nil {
		return fmt.Errorf("you must init Validator with auth.Verifier. request-id=[%s]", requestId)
	}

	args, err := newWechatpayHeaders(header)
	if err != nil {
		return fmt.Errorf("%w request-id=[%s]", err, requestId)
	}

	message := args.buildMessage(ctx, header, body)
	if err := v.verifier.Verify(ctx, args.SerialNo, message, args.Signature); err != nil {
		return fmt.Errorf("validate verify fail serialNo=%s request-id=[%s] err=%v", args.SerialNo, requestId, err)
	}
	return nil
}

// 微信支付回调信息上下文
type wechatPayHeaders struct {
	SerialNo  string
	Signature string
	Nonce     string
	Timestamp int64
}

func newWechatpayHeaders(headers http.Header) (rs wechatPayHeaders, err error) {
	getHeader := func(name string) (string, error) {
		v := strings.TrimSpace(headers.Get(name))
		if v == "" {
			return v, fmt.Errorf("empty '%s'", name)
		}
		return v, nil
	}
	getHeaderInt64 := func(name string) (int64, error) {
		v, err := getHeader(name)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(v, 10, 64)
	}

	rs.SerialNo, err = getHeader(consts.WechatPaySerial)
	if err != nil {
		return
	}
	rs.Signature, err = getHeader(consts.WechatPaySignature)
	if err != nil {
		return
	}
	rs.Nonce, err = getHeader(consts.WechatPayNonce)
	if err != nil {
		return
	}
	rs.Timestamp, err = getHeaderInt64(consts.WechatPayTimestamp)
	if err != nil {
		return
	}

	now := time.Now()
	if math.Abs(float64(rs.Timestamp-now.Unix())) >= consts.FiveMinute {
		err = fmt.Errorf("notify expired. timestamp=[%d]", rs.Timestamp)
	}
	return
}

func (h *wechatPayHeaders) buildMessage(ctx context.Context, header http.Header, body []byte) string {
	return fmt.Sprintf("%d\n%s\n%s\n", h.Timestamp, h.Nonce, string(body))
}
