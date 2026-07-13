# Ruibo 内部代码签名

## 结论

- Sciter 是界面框架，不是键盘或鼠标驱动。
- 当前客户端的 Map、Translate、Legacy、Auto 是键码转换模式，Windows 端最终仍使用合成输入。
- 安装包中的 `usbmmidd` 是虚拟显示驱动，打印机目录是打印驱动；两者都不能修复键盘输入。
- `ruibo.exe --service` 就是 Windows 服务进程，没有单独的 `ruibo_service.exe`。

## 1. 在隔离的 CA 机器生成证书链

```powershell
powershell -ExecutionPolicy Bypass -File .\New-RuiboCertificateChain.ps1 `
  -OutputDirectory D:\Ruibo-PKI -ExportRootBackup
```

脚本会分别询问代码签名 PFX 和根 CA 备份密码。生成后：

- `public` 目录可以部署到受控电脑。
- `private\RuiboCodeSigning.pfx` 只放在签名机器或 CI 密钥库中。
- `private\RuiboRootCA-backup.pfx` 应移入离线加密介质。
- 私钥、密码和 PFX 禁止进入客户端安装包、Git 仓库或普通共享盘。

## 2. 正确的签名顺序

签名机器需安装 Windows 10/11 SDK 的 **Signing Tools for Desktop Apps** 组件，确保能找到 `signtool.exe`。

先签名构建目录中的 Ruibo 自有文件，再制作自解压 EXE/MSI，最后签名安装包：

```powershell
.\Sign-RuiboArtifacts.ps1 `
  -ArtifactsPath D:\build\rustdesk `
  -PfxPath D:\Ruibo-PKI\private\RuiboCodeSigning.pfx

# 完成 portable packer 和 MSI 构建后再次执行
.\Sign-RuiboArtifacts.ps1 `
  -ArtifactsPath D:\build\SignOutput `
  -PfxPath D:\Ruibo-PKI\private\RuiboCodeSigning.pfx
```

如需 RFC 3161 时间戳，可增加 `-TimestampUrl`。签名脚本把 PFX 临时导入当前用户证书库，通过指纹调用 SignTool，密码不会出现在 SignTool 命令行中。

CI 可以把 PFX 密码放入受保护的 `RUIBO_SIGNING_PFX_PASSWORD` 环境变量；不要把密码写进 YAML、参数列表或仓库文件。

脚本默认只签 Ruibo 自有的 EXE、DLL、MSI，并排除 `drivers` 和 `usbmmidd_v2`。不要用内部应用证书覆盖第三方驱动的 CAT/SYS/DLL 签名。

签名脚本会从 PFX 相邻的 `public\RuiboRootCA.cer` 自动找到公开根证书，也可用 `-RootCertificatePath` 指定。根证书只会临时进入签名账号的 `CurrentUser\Root` 以执行 SignTool 链验证，脚本退出时会自动移除原本不存在的临时信任。

## 3. 在受控电脑一键建立信任

将完整的 `public` 目录复制到电脑后，以管理员身份双击：

```text
Install-RuiboTrust.cmd
```

导入前也可以只做指纹、CA 约束和代码签名 EKU 检查，不修改证书库：

```powershell
.\Install-RuiboTrust.ps1 -ValidateOnly
```

它会按 `certificate-manifest.json` 校验固定指纹，只将根 CA 导入 `LocalMachine\Root`，将代码签名叶证书导入 `LocalMachine\TrustedPublisher`。撤销信任时双击 `Remove-RuiboTrust.cmd`。

域环境优先用组策略或 MDM 分发这两个公共证书，而不是逐台运行脚本。

## 4. 关于真正的键鼠驱动模式

若以后确实需要绕开 `SendInput`，应单独开发 Windows KMDF/VHF 虚拟 HID 源驱动、受限 IOCTL 接口、服务端发送逻辑、卸载/升级回滚和设备访问控制。该驱动必须经过 WDK/HLK 测试并取得符合目标 Windows 版本要求的驱动签名。内部自建根证书适合应用 Authenticode 和受控测试，不等于面向正常 Windows 安全启动环境的生产内核驱动签名。
