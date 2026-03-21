# Unauthorized File Upload Vulnerability Report

## Affected Product

Acrel Co., Ltd. is a company based in China.
The official website is: [https://www.acreldny.cn](https://www.acreldny.cn)

One of its products, **Acrel Environmental Electricity Supervision Cloud Platform**, contains an **unauthorized file upload vulnerability** discovered through source code auditing.

---

# Affected Source Code Locations

The following source code files contain vulnerable upload logic:

```
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/EquipmentController.cs:13
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/EquipmentController.cs:32
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/NewsManageController.cs:65
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/NewsManageController.cs:93
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/APPController.cs:15
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/APPController.cs:766
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/APPController.cs:792
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/AppManagerController.cs:12
bin/CS/JuCheap.Web/JuCheap.Web.Controllers/AppManagerController.cs:243
bin/CS/JuCheap.Services/JuCheap.Services.shareApi/EventApi.cs:861
bin/CS/JuCheap.Services/JuCheap.Services.shareApi/EventApi.cs:891
```

---

# Root Cause of the Vulnerability

The vulnerability is caused by improper validation in multiple file upload interfaces.

Main issues include:

1. **Anonymous access enabled**

Some controllers allow unauthenticated access through attributes such as:

```
[AllowAnonymous]
```

Examples:

```
APPController
AppManagerController
```

2. **Client-controlled file extension**

The upload logic directly concatenates file extensions provided by the client:

```
string path = picPath + "\\" + newFileName + "." + fileformat;
```

or

```
string extension = file.FileName.Substring(file.FileName.LastIndexOf('.')).ToLower();
```

This allows attackers to upload arbitrary file types.

3. **Lack of security validation**

The system only performs basic size restrictions (e.g., 2MB) but **does not implement proper security checks**, including:

- File extension whitelist
- MIME type validation
- File magic number verification

4. **Files saved in web-accessible directories**

Uploaded files are stored directly in web-accessible paths such as:

```
/UpLoad/Temp
/UpLoad/EventVideo
```

As a result, attackers can upload malicious files and access them through HTTP.

---

# Proof of Concept (Real Test Results)

The following production systems were tested and confirmed vulnerable:

### Target 1

```
http://39.104.75.178
```

Vulnerable endpoint:

```
/api/APP/uploadVideo
```

Result:

- File upload succeeded without authentication
- Uploaded file could be accessed and downloaded

---

### Target 2

```
http://61.136.168.226:8081
```

Vulnerable endpoints:

```
/api/APP/uploadVideo
/api/APP/uploadAttachment
/api/AppManager/uploadAttachment
```

Result:

- All endpoints allow **unauthorized file upload**
- Uploaded files are accessible via HTTP

---

# Vulnerable Code Details

## 1. Anonymous Access Controllers

APPController.cs

```
[AllowAnonymous]
[AllowCrossSiteJson]
public class APPController : ApiController
```

AppManagerController.cs

```
[AllowAnonymous]
[AllowCrossSiteJson]
public class AppManagerController : ApiController
```

---

## 2. Upload Interfaces Without Security Controls

APPController.cs

```
public HttpResponseMessage uploadAttachment(EventHandleSaveFilter filter)
{
    string jsons = new AppManagerService().uploadAttachment(filter);
}
```

```
public HttpResponseMessage uploadVideo()
{
    string jsons = new APPService().uploadVideo();
}
```

AppManagerController.cs

```
public HttpResponseMessage uploadAttachment(EventHandleSaveFilter filter)
{
    string jsons = new AppManagerService().uploadAttachment(filter);
}
```

---

## 3. Critical Vulnerable Logic (Direct Disk Write)

### EventApi.cs

Client-controlled file extension:

```
string path = picPath + "\\" + newFileName + "." + fileformat;
byte[] arr = Convert.FromBase64String(fileByteStr);
using FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write);
fs.Write(arr, 0, arr.Length);
returnHt.Add("filePaht", "/UpLoad/Temp/" + newFileName + "." + fileformat);
```

Original filename extension used directly:

```
string extension = file.FileName.Substring(file.FileName.LastIndexOf('.')).ToLower();
string filepath = path + "\\" + newFileName + extension;
file.SaveAs(filepath);
returnHt.Add("filePaht", "/UpLoad/EventVideo/" + newFileName + extension);
```

### EquipmentController.cs

```
string ex = Path.GetExtension(file.FileName);
filePathName = Guid.NewGuid().ToString("N") + ex;
file.SaveAs(Path.Combine(localPath, filePathName));
```

### NewsManageController.cs

```
string fileFormat = file.FileName.Substring(file.FileName.LastIndexOf(".") + 1).ToLower();
string filepath = picPath + "\\" + newFileName + "." + fileFormat;
file.SaveAs(filepath);
```

---

# Exploitable Call Chain

The following request paths can trigger the vulnerability.

### Chain 1

```
/api/APP/uploadAttachment
  → APPController.uploadAttachment
  → AppManagerService.uploadAttachment
  → EventApi.uploadFileTemp
```

Attacker-controlled parameter:

```
fileformat
```

---

### Chain 2

```
/api/AppManager/uploadAttachment
  → AppManagerController.uploadAttachment
  → AppManagerService.uploadAttachment
  → EventApi.uploadFileTemp
```

---

### Chain 3

```
/api/APP/uploadVideo
  → APPController.uploadVideo
  → APPService.uploadVideo
  → EventApi.uploadVideoTemp
```

Uses original file extension from client.

---

### Chain 4

Direct upload endpoints:

```
/Equipment/UpLoadPic
/NewsManage/UploadNewsImg
```

These directly call:

```
file.SaveAs()
```

without proper validation.

---

# Security Impact

Attackers can exploit this vulnerability to:

- Upload arbitrary files
- Upload malicious scripts or webshells
- Achieve remote code execution
- Gain persistent access to the server
- Compromise the entire web system

---

# Recommended Fix

1. **Disable anonymous access for upload interfaces**

Remove:

```
[AllowAnonymous]
```

2. **Implement strict file extension whitelist**

Example:

```
jpg
png
jpeg
mp4
pdf
```

3. **Validate MIME type**

Verify the Content-Type header and actual file content.

4. **Verify file magic number**

Ensure uploaded files match the expected file signature.

5. **Store files outside web root**

Example:

```
/data/upload
```

instead of:

```
/UpLoad
```

6. **Rename files securely and prevent execution**

For example:

```
randomUUID + safe extension
```
