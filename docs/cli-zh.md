# Spark CLI

CLI 是当前第一个可实际使用的客户端。它通过 `spark-net` 连接服务，支持一次性命令和持续聊天。每次启动都从加密钥匙串恢复账户状态，不在本地保存聊天历史。

## 构建与启动

```sh
cargo build -p spark-cli
alias spark="$PWD/target/debug/spark"
spark help
spark serve
```

`serve` 默认监听本机的 9310、9311、9312 端口，启动时显示 `pin`。数据、服务端签名密钥和 TLS 身份保存在 `spark-server-data`，可用 `serve --data-dir DIR` 指定目录；目录权限必须为 0700，同目录只能启动一个服务进程。重启保留数据和 pin。备份时停止服务后复制整个私有目录，不能只复制正在使用的 SQLite 主文件而漏掉 WAL。保持这个终端运行，在其他终端配置账户。每个终端都需设置上述 alias，或直接使用二进制路径。

**这个服务器仍用于开发：数据只在内存中，停止进程会丢失全部服务端数据，TLS pin 也会改变。** 下文验证的是客户端退出、重开和恢复；服务端重启后的恢复需要后续持久化工作。请勿把它用于唯一一份真实聊天记录。

## 两个账户开始聊天

在第二个终端，把 `PIN` 替换成服务启动时显示的完整值：

```sh
PIN='服务器显示的64位十六进制pin'
spark init ./alice --pin "$PIN" --tor off
spark init ./bob --pin "$PIN" --tor off
spark account ./alice
spark account ./bob
```

默认 Tor 模式为 `text`：控制和文字走 Tor，媒体直连。上述本机演示明确关闭 Tor。连接远程服务时，用 `--keyring HOST:PORT --content HOST:PORT --issuer HOST:PORT` 指定地址；用 `--proxy HOST:PORT` 指定 Tor SOCKS5 代理，默认 `127.0.0.1:9050`。pin 应通过可信渠道取得，不提供跳过证书校验的选项。

`init` 显示新账户的 24 个助记词，请另行安全备份。账户目录权限为 `0700`，其中 `profile.json` 权限为 `0600`，**包含未加密的助记词**和连接设置。当前支持 macOS/Linux，本机有权限读取这个文件的人就持有账户。不要上传到 Git、共享磁盘或公开云盘。

创建房间并邀请 Bob：

```sh
ROOM=$(spark create ./alice '我们的房间')
spark key-package ./bob ./bob.package
spark invite ./alice "$ROOM" ./bob.package ./bob.invitation
spark join ./bob ./bob.invitation '我们的房间'
spark send ./alice "$ROOM" '你好，Bob'
spark send ./bob "$ROOM" '收到'
spark history ./alice "$ROOM"
spark rooms ./bob
```

每条命令都是独立进程，可以退出后再继续。`key-package` 会先把接受邀请所需的私密状态保存到加密钥匙串，再输出公开的 package。Bob 把 package 交给 Alice，Alice 把 invitation 交回 Bob；**invitation 包含历史解密密钥，必须通过保密渠道传递**。各输出文件都不会覆盖已有文件。

## 持续聊天

在两个终端分别运行（把 ROOM 替换成 `rooms` 列出的完整房间 ID）：

```sh
spark chat ./alice ROOM
spark chat ./bob ROOM
```

直接输入消息并按 Enter。客户端每隔约两秒轮询一次，显示历史及新消息。

- `/quit`：退出，也可通过 Ctrl-D 或 Ctrl-C 退出。
- `/share 路径`：上传附件，并将下载句柄发到房间。路径有空格时直接输入，不加引号。
- `/help`：显示聊天命令。
- `//文字`：发送以 `/` 开头的文字，例如 `//help` 会发送 `/help`。

聊天期间，同一个本地 profile 被锁定，避免另一个命令覆盖其状态。退出聊天后再执行其他账户命令。操作系统会在进程退出或崩溃后释放锁，残留的 `lock` 文件无需删除。**同一账户不要在不同 profile 或设备上同时写入**；当前并未解决跨设备并发写入。

连接断开后会尝试重连。离线输入不会排队发送；如果写入失败，客户端不会自动重发，因为服务器可能已经收到消息。先查历史，再决定是否重试。重连需要服务端数据和 pin 仍然有效。网络调用仍使用现有同步传输，网络黑洞下可能要等系统超时；这不是离线消息队列或完整的断线恢复协议。

## 附件与脚本输入

```sh
spark share ./alice ROOM ./photo.png
spark fetch ./bob 'spark-file:名称:密钥' ./received.png
printf '第一行\n第二行\n' | spark send ./alice ROOM -
```

`share` 会输出并发送 `spark-file:…` 下载句柄，其他成员可从历史中复制它。句柄本身包含解密能力，应像附件内容一样保密。照片经过已有的元数据清理流程，不支持安全清理的媒体格式会被拒绝。下载不覆盖已有文件。终端会转义消息中的控制字符，防止消息执行终端转义操作。

## 从助记词恢复

把之前备份的 24 个助记词放入一个安全的本地文件：

```sh
spark init ./restored --pin "$PIN" --tor off --phrase-file ./recovery.txt
spark rooms ./restored
spark history ./restored ROOM
spark send ./restored ROOM '恢复后继续聊天'
```

也可用 `--phrase-file -` 从标准输入读入。助记词不作为命令行参数传入。恢复不需要复制旧 profile 的其他文件，但需要原服务仍持有加密数据。服务端内容丢失时，助记词无法重新生成聊天记录。

## 验证范围

`cargo test -p spark-cli --test terminal` 使用真正的 CLI 子进程和本机 TLS 服务，覆盖退出后接受邀请、跨进程收发、重新恢复后发送、附件、持续接收重复内容、profile 互斥、文件权限和终端转义。原有 `new`、`demo`、`remote-demo`、`serve` 命令仍保留。

本次不包含服务端持久化、生产支付、后台推送或手机 App；掩护流量仍通过原有 `remote-demo --cover` 验证，交互式 CLI 尚未提供该设置。

## Contacts 白名单

默认不接收陌生人的联系人请求。`account PROFILE` 显示自己的 public identity。

- `contacts PROFILE`：列出已批准的联系人。
- `contact-add PROFILE NAME PUBLIC_OR_CARD_HEX`：明确批准对方身份，输出自己的回信卡片。
- 将卡片通过可信的保密渠道交给对方；对方也运行 `contact-add` 并将回信卡片交回来，再导入即可双向通信。卡片包含 inbox 授权凭证，不应公开。
- `contact-note PROFILE SIGNING_KEY_HEX TEXT`：发送签名加密的联系人留言（KEY 为 public identity 的前 32 字节）。
- `inbox PROFILE`：读取来自已批准联系人的留言。
- `contact-remove PROFILE SIGNING_KEY_HEX`：移除联系人并撤销权限。

每个联系人最多一个待处理留言；更新白名单会清空待处理收件箱。名单和身份只保存在加密 keyring，服务端仅持有有数量上限的随机授权凭证哈希。

上传断线后使用 `spark retry-upload PROFILE` 续办原操作。未完成的上传会阻止新的发送；恢复会重用已保存的原请求，避免重复扣款。多设备快照发生冲突时需重新打开账户加载最新状态。
