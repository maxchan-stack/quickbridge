# QuickBridge

免費、免安裝、免註冊的跨裝置端對端加密傳檔與文字傳輸工具。

- 網站：https://maxchan-stack.github.io/quickbridge/
- 傳輸架構：GitHub Pages 靜態前端 ＋ Cloudflare Workers ＆ Durable Objects（WebSocket Hibernation API 二進位加密中繼）

## 核心規格與安全機制

- **雙模式快速配對**：建立房間後同時提供 **QR Code** 與 **6 位數短碼**（例如 `482-915`），不方便掃碼時可於另一台裝置直接輸入短碼連線；短碼未配對時 5 分鐘自動失效。
- **跨網路穿透**：全程透過 HTTPS／WSS（Port 443）連線，支援校園乙太網路、企業防火牆與手機 4G／5G（CGNAT）。
- **傳輸上限與多檔佇列**：單檔上限 **20 MB**，單一房間雙向各 **60 MB** 累計額度，支援一次選取或拖放多個檔案依序傳送，並顯示即時 MB 傳輸進度；房間閒置 15 分鐘自動關閉。
- **端對端加密（E2EE）**：
  - 雙方加入後執行臨時 **ECDH（P-256）** 金鑰交換並透過 **HKDF-SHA-256** 派生會話金鑰，全程以 **AES-GCM 256-bit** 加密，搭配 AAD（房號、角色、階段、遞增序號）防重放與亂序。
  - 雙方以臨時公鑰計算 8 碼驗證碼（`XXXX-XXXX`），須人工確認相同後才解鎖傳輸，防範中間人攻擊與短碼誤連。
- **檔案完整性與防護**：
  - 64 KiB 分塊與滑動視窗流控、緩衝排空確認、接收端顯式確認、**SHA-256** 雜湊驗證與檔名淨化。
  - QR Code 函式庫已本地化（`vendor/qrcode.min.js`），不依賴外部 CDN。
  - 中繼伺服器僅瞬時轉發密文，不落地儲存檔案，並嚴格驗證 `Origin` 來源。

## 部署方式

### 1. Cloudflare Worker（免信用卡免費方案）

```bash
cd worker
npx wrangler deploy
```

`worker/wrangler.toml` 已配置 SQLite-backed Durable Objects（`new_sqlite_classes = ["Room"]`）與 `ALLOWED_ORIGINS`，可直接部署於 Cloudflare Workers Free Plan（無須綁定信用卡）。

### 2. GitHub Pages

於 GitHub Repository 的 **Settings → Pages → Build and deployment → Source** 選擇 **GitHub Actions**。推送至 `main` 分支時，`.github/workflows/pages.yml` 會自動執行語法檢查、單元測試，並僅打包靜態前端檔案發布。

## 本地測試

```bash
node --check app.js
node --check worker/src/index.js
node --test tests/*.test.mjs
```

## 安全與隱私注意事項

- 於學校或公共電腦使用完畢後，請點擊「結束房間」以清除畫面紀錄與記憶體物件，並手動刪除電腦「下載」資料夾中的已下載檔案。
- 請務必核對兩端 8 碼驗證碼一致後再傳送檔案或文字。
