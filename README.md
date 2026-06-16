# recon0x-content

recon0x の記事コンテンツリポジトリ。

## 構成

```
articles/
└── {slug}/
    ├── index.mdx     ← 記事本文(MDX)
    └── images/
        ├── hero.png  ← ヒーロー画像
        ├── 1.png     ← 本文中の画像
        ├── 2.png
        └── ...
```

## 記事の追加方法

1. `articles/{slug}/` ディレクトリを作成
2. `index.mdx` を配置(フロントマター必須)
3. 画像を `images/` に配置
4. `git push origin main`
5. recon0x 本体が 1 時間以内に自動反映(Vercel ISR)

## フロントマター必須フィールド

```yaml
---
title: "記事タイトル"
slug: "slug-name"
field: "Web"           # Web / Linux / Network / Crypto / Pwn / Forensic / OSINT
level: "L2"            # L1 / L2 / L3 / L4 / L5
readMin: 20
publishedAt: "2026-06-16"
description: "記事の概要(1-2 行)"
tags: ["sqli", "owasp"]
prerequisites: ["http-basics"]
heroImage: "/articles/sqli-basics/hero.png"
---
```

## 即時反映させたい場合

recon0x 本体で以下を実行:

```bash
# Vercel の ISR キャッシュを手動クリア(要 CRON_SECRET 設定)
curl -X POST https://recon.tech/api/revalidate \
  -H "Authorization: Bearer $CRON_SECRET" \
  -d '{"slug": "sqli-basics"}'
```
