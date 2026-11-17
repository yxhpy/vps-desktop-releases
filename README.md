# Claude VPS 桌面 App 下载

这里只放 Claude VPS 桌面 App 的安装包和更新文件，不放 App 的源代码。

## 下载

- macOS（Apple 芯片）：[Claude-VPS-macos-arm64.dmg](https://github.com/yxhpy/vps-desktop-releases/releases/latest/download/Claude-VPS-macos-arm64.dmg)

Windows 和 Linux 版还没有。

## 第一次打开

1. 双击下载的 `.dmg`，把 Claude VPS 拖进「应用程序」。
2. 在「应用程序」里打开 Claude VPS。这个 App 没有购买 Apple 的开发者证书，第一次打开时 macOS 会拦一下：打开「系统设置 → 隐私与安全性」，在下方找到 Claude VPS，点「仍要打开」，再确认一次。
3. 用门户的账号登录。

## 更新

装好以后不用再回这里。有新版本时，App 顶部会出现「有新版本」，点「更新并重启」就行。App 只安装用发布者私钥签过名、并且签名里写明了这个版本号的更新包；对不上就不装，原来的 App 照常可用。

## 这里的文件

| 文件 | 用途 |
|---|---|
| `Claude-VPS-macos-arm64.dmg` | 第一次安装 |
| `Claude-VPS-macos-arm64.app.tar.gz` 和同名 `.sig` | App 自动更新用的安装包和它的签名 |
| `latest.json` | 告诉 App 最新版本是哪个、去哪下载 |
| `components.json` 和 `components-b.json`（在「components」这个发布里） | App 安装 Claude Code、Claude Desktop 和 CC Switch 时用的清单，两份内容相同、轮流更新 |

组件清单每 6 小时由本仓库的 Actions 重新生成并签名。每次只替换两份里较旧的那份，所以任何时候线上都有一份完整的清单，App 取两份里较新的一份：

- `components.py` 从各自的官方来源取最新版本，逐个校验后列出；
- `manifest/` 用 App 自己的校验代码签名，App 不会接受的清单不会被签出来；
- `.github/workflows/components.yml` 是这个定时任务。
