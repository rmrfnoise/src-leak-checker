# src-leak-checker

根目录备份 / 源码压缩包泄露自查工具，仅限授权目标使用。

## 使用

要求 Python 3.9+。

创建虚拟环境：

```bash
python -m venv .venv
```

激活虚拟环境：

- Windows PowerShell：`.venv\Scripts\Activate.ps1`
- Windows cmd：`.venv\Scripts\activate.bat`
- macOS / Linux：`source .venv/bin/activate`

安装依赖：

```bash
python -m pip install -r requirements.txt
```

扫描一个目标：

```bash
python src_leak_scan.py -u https://example.com
```

可选参数：

- `-t, --threads N`：并发线程数，默认 10
- `-k, --insecure`：忽略 TLS 证书错误
