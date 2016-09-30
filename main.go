package main

import (
	"time"
	"strconv"
	"encoding/json"
	"fmt"
	"encoding/base64"
	"sort"
	"net/url"
	"bytes"
	"reflect"
	"strings"
	"crypto/sha1"
	"flag"
	"os"
	"io"
	"bufio"
	"crypto/sha256"
	"net/http"
	"io/ioutil"
)

type H5PayRequest struct {
	Attach     string `json:"attach,omitempty" url:"attach,omitempty"`       //透传参数
	Busicd     string `json:"busicd" url:"busicd"`                           //交易类型
	BackUrl    string `json:"backUrl,omitempty" url:"backUrl,omitempty"`     //异步通知接收地址
	Chcd       string `json:"chcd" url:"chcd"`                               //支付渠道代码   WXP:ALP
	FrontUrl   string `json:"frontUrl" url:"frontUrl"`                       //支付成功或失败后跳转到的url
	GoodsInfo  string `json:"goodsInfo,omitempty" url:"goodsInfo,omitempty"` //订单商品详情
	Mchntid    string `json:"mchntid" url:"mchntid"`                         //商户号
	OrderNum   string `json:"orderNum" url:"orderNum"`                       //订单号
	Txamt      string `json:"txamt" url:"txamt"`                             //订单金额
	Sign       string `json:"sign" url:"-"`                                  //签名
	Terminalid string `json:"terminalid" url:"terminalid"`                   //终端号
	Version    string `json:"version" url:"version"`                         //版本号
}

var Domain string

func main() {
	filepath := flag.String("f", "example.conf", "gen url by conf")
	flag.Parse()

	req := encapRequestData(*filepath)
	respBytes :=postScanpayReq(req)
	marshalRespBytes(respBytes,req.Chcd)

}
func encapConfigData(path string) (h5 *H5PayRequest) {
	node := "h5"
	c := Config{}
	c.InitConfig(path)
	//for k,v:=range c.Mymap{
	//	fmt.Printf("k:%s v:%s\n",k,v)
	//}
	h5 = &H5PayRequest{}
	h5.OrderNum = strconv.Itoa(int(time.Now().UnixNano()))
	h5.Attach = c.Read(node, "attach")
	h5.BackUrl = c.Read(node, "backUrl")
	h5.Busicd = c.Read(node, "busicd")
	h5.Chcd = c.Read(node, "chcd")
	h5.FrontUrl = c.Read(node, "frontUrl")
	h5.GoodsInfo = c.Read(node, "goodsInfo")
	h5.Mchntid = c.Read(node, "mchntid")
	h5.Txamt = c.Read(node, "txamt")
	h5.Terminalid = c.Read(node, "terminalid")
	h5.Version = c.Read(node, "version")
	theSignKey := c.Read(node, "signKey")
	Domain = c.Read(node, "domain")
	h5.Sign = signWithSha1(h5, theSignKey)
	return

}
func genUrl(h5 *H5PayRequest) {
	bytes, _ := json.Marshal(h5)
	fmt.Printf("json: ==>%s\n", bytes)
	b64str := base64.StdEncoding.EncodeToString(bytes)
	url := Domain + "?data=" + b64str
	fmt.Println(url + "\n")
}
func signWithSha1(s interface{}, signKey string) string {
	signBuffer, _ := Query(s)
	signString := signBuffer.String() + signKey
	fmt.Printf("sign string==> %s\n", signString)
	//h:=sha1.New()
	//h.Write([]byte(signString))
	//signBytes:=h.Sum(nil)
	signBytes := sha1.Sum([]byte(signString))
	//fmt.Printf("sign\n  %v\n\n",signBytes)
	signString = fmt.Sprintf("%x", signBytes)
	return signString
}

func encapRequestData(path string) (req *ScanPayRequest) {
	node := "scanpay"
	c := Config{}
	c.InitConfig(path)
	for k,v:=range c.Mymap{
		fmt.Printf("k:%s v:%s\n",k,v)
	}
	req = &ScanPayRequest{}
	req.OrderNum = strconv.Itoa(int(time.Now().UnixNano()))
	req.Txndir = c.Read(node, "txndir")
	req.Busicd = c.Read(node,"busicd")
	req.AgentCode = c.Read(node,"inscd")
	req.Chcd =c.Read(node,"chcd")
	req.GoodsList = `[{"goodsId":"iphone6s_16G","unifiedGoodsId":"1001", "goodsName":"iPhone6s 16G","goodsNum":"1","price":"528800","goodsCategory":"123456","body":"苹果手机"},{"goodsId":"iphone6s_16G","unifiedGoodsId":"1001", "goodsName":"iPhone6s 16G","goodsNum":"1","price":"528800","goodsCategory":"123456","body":"苹果手机","showUrl":"www.lalala.com"}]`
	req.Mchntid = c.Read(node,"mchntid")
	req.Txamt = c.Read(node,"txamt")
	req.Terminalid = c.Read(node,"terminalid")
	req.Currency = c.Read(node,"currency")
	req.Version = c.Read(node,"version")
	req.OutOrderNum = c.Read(node,"outOrderNum")
	theSignKey := c.Read(node, "signKey")
	Domain = c.Read(node, "domain")

	req.Sign = signWithSha256(req, theSignKey)
	return
}

func marshalRespBytes(bytes []byte,chanCode string){

}
func postScanpayReq(req *ScanPayRequest) []byte{
	reqBytes,_:=json.Marshal(req)
	body := bytes.NewBuffer([]byte(reqBytes))
	res,err := http.Post(Domain, "application/json;charset=utf-8", body)
	if err!=nil{
		fmt.Print("post err %s",err)
	}
	defer res.Body.Close()
	result, _ := ioutil.ReadAll(res.Body)
	return result

}
func signWithSha256(req *ScanPayRequest, key string) string {
	signBuffer, _ := Query(req)
	signString := signBuffer.String() + key
	fmt.Printf("sign string==> %s\n", signString)
	//h:=sha1.New()
	//h.Write([]byte(signString))
	//signBytes:=h.Sum(nil)
	signBytes := sha256.Sum256([]byte(signString))
	//fmt.Printf("sign\n  %v\n\n",signBytes)
	signString = fmt.Sprintf("%x", signBytes)
	return signString
}
func Query(s interface{}, excludes ...string) (buf bytes.Buffer, err error) {
	if s == nil {
		return
	}

	v, err := Values(s)
	if err != nil {
		return buf, err
	}

	return QueryValues(v), nil
}

// QueryValues implements encoding of values into URL query parameters without escape
func QueryValues(v url.Values, excludes ...string) (buf bytes.Buffer) {
	if v == nil {
		return
	}

	keys := make([]string, 0, len(v))
	for k := range v {
		if StringInSlice(k, excludes) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		vs := v[k]
		prefix := k + "="
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(prefix)
			buf.WriteString(v)
		}
	}
	return buf

}
func StringInSlice(a string, list []string) bool {
	if len(list) == 0 {
		return false
	}
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

var timeType = reflect.TypeOf(time.Time{})

var encoderType = reflect.TypeOf(new(Encoder)).Elem()

type Encoder interface {
	EncodeValues(key string, v *url.Values) error
}

func Values(v interface{}) (url.Values, error) {
	values := make(url.Values)
	val := reflect.ValueOf(v)
	for val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return values, nil
		}
		val = val.Elem()
	}

	if v == nil {
		return values, nil
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("query: Values() expects struct input. Got %v", val.Kind())
	}

	err := reflectValue(values, val, "")
	return values, err
}

func reflectValue(values url.Values, val reflect.Value, scope string) error {
	var embedded []reflect.Value

	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		sf := typ.Field(i)
		if sf.PkgPath != "" && !sf.Anonymous {
			// unexported
			continue
		}

		sv := val.Field(i)
		tag := sf.Tag.Get("url")
		if tag == "-" {
			continue
		}
		name, opts := parseTag(tag)
		if name == "" {
			if sf.Anonymous && sv.Kind() == reflect.Struct {
				// save embedded struct for later processing
				embedded = append(embedded, sv)
				continue
			}

			name = sf.Name
		}

		if scope != "" {
			name = scope + "[" + name + "]"
		}

		if opts.Contains("omitempty") && isEmptyValue(sv) {
			continue
		}

		if sv.Type().Implements(encoderType) {
			if !reflect.Indirect(sv).IsValid() {
				sv = reflect.New(sv.Type().Elem())
			}

			m := sv.Interface().(Encoder)
			if err := m.EncodeValues(name, &values); err != nil {
				return err
			}
			continue
		}

		if sv.Kind() == reflect.Slice || sv.Kind() == reflect.Array {
			var del byte
			if opts.Contains("comma") {
				del = ','
			} else if opts.Contains("space") {
				del = ' '
			} else if opts.Contains("semicolon") {
				del = ';'
			} else if opts.Contains("brackets") {
				name = name + "[]"
			}

			if del != 0 {
				s := new(bytes.Buffer)
				first := true
				for i := 0; i < sv.Len(); i++ {
					if first {
						first = false
					} else {
						s.WriteByte(del)
					}
					s.WriteString(valueString(sv.Index(i), opts))
				}
				values.Add(name, s.String())
			} else {
				for i := 0; i < sv.Len(); i++ {
					k := name
					if opts.Contains("numbered") {
						k = fmt.Sprintf("%s%d", name, i)
					}
					values.Add(k, valueString(sv.Index(i), opts))
				}
			}
			continue
		}

		if sv.Type() == timeType {
			values.Add(name, valueString(sv, opts))
			continue
		}

		for sv.Kind() == reflect.Ptr {
			if sv.IsNil() {
				break
			}
			sv = sv.Elem()
		}

		if sv.Kind() == reflect.Struct {
			reflectValue(values, sv, name)
			continue
		}

		values.Add(name, valueString(sv, opts))
	}

	for _, f := range embedded {
		if err := reflectValue(values, f, scope); err != nil {
			return err
		}
	}

	return nil
}

// valueString returns the string representation of a value.
func valueString(v reflect.Value, opts tagOptions) string {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	if v.Kind() == reflect.Bool && opts.Contains("int") {
		if v.Bool() {
			return "1"
		}
		return "0"
	}

	if v.Type() == timeType {
		t := v.Interface().(time.Time)
		if opts.Contains("unix") {
			return strconv.FormatInt(t.Unix(), 10)
		}
		return t.Format(time.RFC3339)
	}

	return fmt.Sprint(v.Interface())
}

// isEmptyValue checks if a value should be considered empty for the purposes
// of omitting fields with the "omitempty" option.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}

	if v.Type() == timeType {
		return v.Interface().(time.Time).IsZero()
	}

	return false
}

// tagOptions is the string following a comma in a struct field's "url" tag, or
// the empty string. It does not include the leading comma.
type tagOptions []string

// parseTag splits a struct field's url tag into its name and comma-separated
// options.
func parseTag(tag string) (string, tagOptions) {
	s := strings.Split(tag, ",")
	return s[0], s[1:]
}

// Contains checks whether the tagOptions contains the specified option.
func (o tagOptions) Contains(option string) bool {
	for _, s := range o {
		if s == option {
			return true
		}
	}
	return false
}

const middle = "========="

type Config struct {
	Mymap  map[string]string
	strcet string
}

func (c *Config) InitConfig(path string) {
	c.Mymap = make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		s := strings.TrimSpace(string(b))
		//fmt.Println(s)
		if strings.Index(s, "#") == 0 {
			continue
		}

		n1 := strings.Index(s, "[")
		n2 := strings.LastIndex(s, "]")
		if n1 > -1 && n2 > -1 && n2 > n1 + 1 {
			c.strcet = strings.TrimSpace(s[n1 + 1 : n2])
			continue
		}

		if len(c.strcet) == 0 {
			continue
		}
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}

		frist := strings.TrimSpace(s[:index])
		if len(frist) == 0 {
			continue
		}
		second := strings.TrimSpace(s[index + 1:])

		pos := strings.Index(second, "\t#")
		if pos > -1 {
			second = second[0:pos]
		}

		pos = strings.Index(second, " #")
		if pos > -1 {
			second = second[0:pos]
		}

		pos = strings.Index(second, "\t//")
		if pos > -1 {
			second = second[0:pos]
		}

		pos = strings.Index(second, " //")
		if pos > -1 {
			second = second[0:pos]
		}

		if len(second) == 0 {
			continue
		}

		key := c.strcet + middle + frist
		c.Mymap[key] = strings.TrimSpace(second)
	}
}

func (c Config) Read(node, key string) string {
	key = node + middle + key
	v, found := c.Mymap[key]
	if !found {
		return ""
	}
	return v
}

// ScanPayRequest 扫码支付
type ScanPayRequest struct {
	Txndir             string `json:"txndir,omitempty" url:"txndir,omitempty" bson:"txndir,omitempty"`                         // 交易方向
	Busicd             string `json:"busicd,omitempty" url:"busicd,omitempty" bson:"busicd,omitempty"`                         // 交易类型
	AgentCode          string `json:"inscd,omitempty" url:"inscd,omitempty" bson:"inscd,omitempty"`                            // 代理/机构号
	Chcd               string `json:"chcd,omitempty" url:"chcd,omitempty" bson:"chcd,omitempty"`                               // 渠道机构
	Mchntid            string `json:"mchntid,omitempty" url:"mchntid,omitempty" bson:"mchntid,omitempty"`                      // 商户号
	Terminalid         string `json:"terminalid,omitempty" url:"terminalid,omitempty" bson:"terminalid,omitempty"`             // 终端号
	Txamt              string `json:"txamt,omitempty" url:"txamt,omitempty" bson:"txamt,omitempty"`                            // 订单金额
	Currency           string `json:"currency,omitempty" url:"currency,omitempty" bson:"currency,omitempty"`                   // 币种
	GoodsInfo          string `json:"goodsInfo,omitempty" url:"goodsInfo,omitempty" bson:"goodsInfo,omitempty"`                // 商品详情
	OrderNum           string `json:"orderNum,omitempty" url:"orderNum,omitempty" bson:"orderNum,omitempty"`                   // 订单号
	OrigOrderNum       string `json:"origOrderNum,omitempty" url:"origOrderNum,omitempty" bson:"origOrderNum,omitempty"`       // 原订单号
	ScanCodeId         string `json:"scanCodeId,omitempty" url:"scanCodeId,omitempty" bson:"scanCodeId,omitempty"`             // 扫码号
	Sign               string `json:"sign,omitempty" url:"-" bson:"sign,omitempty" `                                           // 签名
	NotifyUrl          string `json:"backUrl,omitempty" url:"backUrl,omitempty" bson:"backUrl,omitempty"`                      // 异步通知地址
	OpenId             string `json:"openid,omitempty" url:"openid,omitempty" bson:"openid,omitempty"`                         // openid
	CheckName          string `json:"checkName,omitempty" url:"checkName,omitempty" bson:"checkName,omitempty"`                // 校验用户姓名选项
	UserName           string `json:"userName,omitempty" url:"userName,omitempty" bson:"userName,omitempty"`                   // 用户名
	Desc               string `json:"desc,omitempty" url:"desc,omitempty" bson:"desc,omitempty"`                               // 描述
	Code               string `json:"code,omitempty" url:"code,omitempty" bson:"code,omitempty"`                               // 认证码
	NeedUserInfo       string `json:"needUserInfo,omitempty" url:"needUserInfo,omitempty" bson:"needUserInfo,omitempty"`       // 是否需要获取用户信息
	VeriCode           string `json:"veriCode,omitempty" url:"veriCode,omitempty" bson:"veriCode,omitempty"`                   // js支付用到的凭证
	Attach             string `json:"attach,omitempty" url:"attach,omitempty" bson:"attach,omitempty"`
	TimeExpire         string `json:"timeExpire,omitempty" url:"timeExpire,omitempty" bson:"timeExpire,omitempty"`             // 过期时间
	Version            string `json:"version,omitempty" url:"version,omitempty" bson:"version,omitempty"`                      // 报文版本号

	TradeFrom          string `json:"tradeFrom,omitempty" url:"tradeFrom,omitempty" bson:"tradeFrom,omitempty"`                // 交易来源
	SettDate           string `json:"settDate,omitempty" url:"settDate,omitempty" bson:"settDate,omitempty"`
	NextOrderNum       string `json:"nextOrderNum,omitempty" url:"nextOrderNum,omitempty" bson:"nextOrderNum,omitempty"`

	DiscountAmt        string `json:"discountAmt,omitempty" url:"discountAmt,omitempty" bson:"discountAmt,omitempty"`          //优惠金额 C 卡券优惠金额，在支付账单中作显示
	IntDiscountAmt     int64  `json:"-" url:"-" bson:"-"`                                                                      //以分为单位优惠金额 辅助字段

																															   // 卡券相关字段
	VeriTime           string `json:"veriTime,omitempty" url:"veriTime,omitempty" bson:"veriTime,omitempty"`                   // 核销次数 C
	Terminalsn         string `json:"terminalsn,omitempty" url:"terminalsn,omitempty" bson:"terminalsn,omitempty"`             // 终端号
	Cardbin            string `json:"cardbin,omitempty" url:"cardbin,omitempty" bson:"cardbin,omitempty"`                      // 银行卡cardbin或者用户标识等 C
	PayType            string `json:"payType,omitempty" url:"payType,omitempty" bson:"payType,omitempty"`                      // 支付方式 c
	CouponOrderNum     string `json:"couponOrderNum,omitempty" url:"couponOrderNum,omitempty" bson:"couponOrderNum,omitempty"` // 辅助字段 卡券的系统订单号
	OrigChanOrderNum   string `json:"-" url:"-" bson:"-"`                                                                      // 辅助字段 原渠道订单号
	OrigSubmitTime     string `json:"-" url:"-" bson:"-"`                                                                      // 辅助字段原交易提交时间
	OrigVeriTime       int    `json:"-" url:"-" bson:"-"`                                                                      // 辅助字段 原交易验证时间
	IntPayType         int    `json:"-" url:"-" bson:"-"`                                                                      // 辅助字段 核销次数
	IntVeriTime        int    `json:"-" url:"-" bson:"-"`
	OrigCardbin        string `json:"-" url:"-" bson:"-"`                                                                      //辅助字段
	OrigScanCodeId     string `json:"-" url:"-" bson:"-"`                                                                      //辅助字段
	CreateTime         string `json:"-" url:"-" bson:"-"`                                                                      // 卡券交易创建时间

																															   //渠道相关字段
	ChnlOrigTxnTime    string `json:"-" url:"-" bson:"-"`                                                                      // 渠道原交易时间
	ChnlOrigOrderNum   string `json:"-" url:"-" bson:"-"`                                                                      // 渠道原交易订单号

																															   // 微信需要的字段
	AppID              string `json:"-" url:"-" bson:"-"`                                                                      // 公众号ID
	SubAppID           string `json:"-" url:"-" bson:"-"`                                                                      // 公众号子ID
	DeviceInfo         string `json:"-" url:"-" bson:"-"`                                                                      // 设备号
	SubMchId           string `json:"-" url:"-" bson:"-"`                                                                      // 子商户
	TotalTxamt         string `json:"-" url:"-" bson:"-"`                                                                      // 订单总金额
	GoodsTag           string `json:"-" url:"-" bson:"-"`                                                                      // 商品标识
	SubOpenID          string `json:"-" url:"-" bson:"-"`                                                                      // 子openid

																															   // 辅助字段
	Subject            string `json:"-" url:"-" bson:"-"`                                                                      // 商品名称
	SysOrderNum        string `json:"-" url:"-" bson:"-"`                                                                      // 渠道交易号
	ActTxamt           string `json:"-" url:"-" bson:"-"`                                                                      // 实际交易金额 不同渠道单位不同
	IntTxamt           int64  `json:"-" url:"-" bson:"-"`                                                                      // 以分为单位的交易金额
	ChanMerId          string `json:"-" url:"-" bson:"-"`                                                                      // 渠道商户Id
	SignKey            string `json:"-" url:"-" bson:"-"`                                                                      // 可能表示md5key等
	ExtendParams       string `json:"-" url:"-" bson:"-"`                                                                      // 业务扩展参数
	PemCert            []byte `json:"-" url:"-" bson:"-"`                                                                      // 商户双向认证证书，如果是大商户模式，用大商户的证书
	PemKey             []byte `json:"-" url:"-" bson:"-"`                                                                      // 商户双向认证密钥，如果是大商户模式，用大商户的密钥
	ReqId              string `json:"-" url:"-" bson:"-"`
	AppAuthToken       string `json:"-" url:"-" bson:"-"`
	SubMerId           string `json:"-" url:"-" bson:"-"`                                                                      // 子商户号,支付宝银行模式需要使用
	TransMode          int    `json:"-" url:"-" bson:"-"`                                                                      // 交易模式，1-ALP1.0 2-ALP2.0withRSA 3-ALP2.0withAUTH 4-ALPbankmode

																															   // 访问方式
	IsGBK              bool     `json:"-" url:"-" bson:"-"`
																															   //M       Merchant `json:"-" url:"-" bson:"-"`
																															   //ChanMer ChanMer  `json:"-" url:"-" bson:"-"` //渠道商户配置
																															   /*TODO 此成员加入后，使用(*model.Trans)类型，取值对其整体赋值，validate处反射出错。原因不明*/
																															   //OrigTrans Trans  `json:"-" url:"-" bson:"-"`//原交易信息
	OrigTransBusicd    string `json:"-" url:"-" bson:"-"`                                                                      //原交易类型   代替OrigTrans，临时使用实现功能

	LimitPay           string `json:"-" url:"-" bson:"-"`                                                                      // 指定支付方式

	NeedAddSpTransColl bool `json:"-" url:"-" bson:"-"`                                                                        // 交易是否需要记入trans.sp表，目前只有取消交易用到这个字段

																															   //Version 2.0
	GoodsList          string        `json:"goodsList,omitempty" bson:"goodsList,omitempty" url:"goodsList,omitempty"`
	OutOrderNum        string        `json:"outOrderNum,omitempty" bson:"outOrderNum,omitempty" url:"outOrderNum,omitempty"`
}