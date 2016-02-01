package gowxutil

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"
)

// accesstoken 微信请求token
var accesstoken string

// tokentime 请求token有效时间
var tokentime int64

// WXMessage 微信交互XML结构定义
type WXMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName,omitempty"`
	FromUserName string   `xml:"FromUserName,omitempty"`
	CreateTime   string   `xml:"CreateTime,omitempty"`
	MsgType      string   `xml:"MsgType,omitempty"`
	Content      string   `xml:"Content,omitempty"`
	MsgID        string   `xml:"MsgId,omitempty"`
	PicURL       string   `xml:"PicUrl,omitempty"`
	MediaID      string   `xml:"MediaId,omitempty"`
	Format       string   `xml:"Format,omitempty"`
	ThumbMediaID string   `xml:"ThumbMediaId,omitempty"`
	LocationX    string   `xml:"Location_X,omitempty"`
	LocationY    string   `xml:"Location_Y,omitempty"`
	Scale        string   `xml:"Scale,omitempty"`
	Label        string   `xml:"Label,omitempty"`
	Title        string   `xml:"Title,omitempty"`
	Description  string   `xml:"Description,omitempty"`
	URL          string   `xml:"Url,omitempty"`
}

// json数据返回时状态数据
type atoken struct {
	accesstoken string `json:access_token`
	expiresin   int64  `json:expires_in`
	errcode     string `json:errcode`
	errmsg      string `json:errmsg`
}

// HTTPSPost 给微信服务器Post数据
func HTTPSPost(url string, sdata []byte) (rdata []byte, err error) {
	body := bytes.NewBuffer(sdata)
	res, err := http.Post(url, "application/json", body)
	if err != nil {
		return
	}
	result, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return
	}
	return result, nil
}

// AccessToken 获取接口调用凭证
func AccessToken(appid string, secret string) (token string, err error) {
	// 判断AccessToken是否已经存在且未过有效期
	if time.Now().Unix() < tokentime {
		return token, nil
	}

	url := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", appid, secret)
	resp, err := http.Get(url)
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return token, err
	}
	var aton atoken
	err = json.Unmarshal(body, &aton)
	if err != nil {
		return token, err
	}
	if aton.errcode != "" {
		return token, errors.New(aton.errcode + aton.errmsg)
	}
	accesstoken = aton.accesstoken

	tokentime = time.Now().Unix() + aton.expiresin - 1200
	return accesstoken, nil
}

// AccessVerify 微信服务器接入验证
func AccessVerify(token string, timestamp string, nonce string, signature string) error {
	tmpstrs := make([]string, 3)
	tmpstrs = append(tmpstrs, token)
	tmpstrs = append(tmpstrs, timestamp)
	tmpstrs = append(tmpstrs, nonce)
	sort.Strings(tmpstrs)
	tmpstr := strings.Join(tmpstrs, "")
	sin := fmt.Sprintf("%x", sha1.Sum([]byte(tmpstr)))
	if sin == signature {
		return nil
	}
	return errors.New("签名校验失败")
}

// UnmarshalXML 解析微信XML数据到WXMessage结构体
func UnmarshalXML(xmldata []byte) (wxmsg WXMessage, err error) {
	err = xml.Unmarshal(xmldata, &wxmsg)
	if err != nil {
		return wxmsg, err
	}
	return
}

// MarshalXML 解析WXMessage结构体数据成xml字符串
func MarshalXML(wxmsg *WXMessage) (data []byte, err error) {
	data, err = xml.Marshal(wxmsg)
	if err != nil {
		return data, err
	}
	return data, nil
}
