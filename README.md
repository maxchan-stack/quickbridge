# QuickBridge

跨平台瀏覽器點對點傳檔 MVP（開發測試版）。

## GitHub Pages

在 Settings → Pages → Build and deployment → Source 選擇 **GitHub Actions**。此提交會觸發 `.github/workflows/pages.yml` 部署。

網站：https://maxchan-stack.github.io/quickbridge/

## Cloudflare 後端（尚未部署）

`worker` 目錄包含 Cloudflare Worker + Durable Object 配對程式。需要在 Cloudflare 部署後，將 `config.js` 的 `REPLACE-ME` 換成實際 workers.dev 網址，網站才可以配對。

## 安全限制

此版本未經跨裝置實測，沒有 TURN、完整性驗證、完整的濫用防護或接收端檔案確認。請勿傳輸學生個資或機密檔案。
