# 2FA TOTP Generator

一个纯前端的 Google Authenticator 风格 2FA 实时验证码页面。

## 功能

- 支持输入 Base32 Secret 即时生成 TOTP 验证码
- 支持粘贴 `otpauth://totp/...` 链接自动解析
- 支持上传二维码图片自动识别其中的 `otpauth://` 或 Base32 Secret
- 支持通过 `?secret=...`、`?uri=...` 或 `?otpauth=...` 预填
- 页面每 30 秒自动刷新验证码，并显示倒计时
- 所有计算都在浏览器本地完成，不依赖后端

## 本地预览

直接双击 [index.html](./index.html) 即可，也可以用任意静态服务器：

```bash
npx serve .
```

## URL 预填示例

```text
/2fa/?secret=YOUR_BASE32_SECRET
/2fa/?uri=otpauth://totp/Example:demo?secret=YOUR_BASE32_SECRET&issuer=Example
```

## 二维码识别说明

- 上传功能优先使用浏览器原生 `BarcodeDetector`
- 推荐使用最新版 Chrome 或 Edge
- 目前不支持 `otpauth-migration://` 这类批量迁移二维码

## 安全提示

- 页面本身不会把 Secret 提交到服务端
- 如果把 Secret 放进 URL，它会进入浏览器历史、日志和分享链路，公开站点不建议长期这样使用
- 如果要处理真实生产密钥，优先部署你自己可控的站点

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=shiro1888/2FA&type=Date)](https://star-history.com/#shiro1888/2FA&Date)
