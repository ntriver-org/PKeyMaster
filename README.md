<p align="center"><img src="https://ntriver.org/img/pkeymaster-logo.png" alt="PKeyMaster Logo"></p>

<h1 align="center">PKeyMaster</h1>

<p align="center">An open-source toolkit for Microsoft product key validation, CID retrieval, and advanced key scanning.</p>

<hr>

## Download / How to use?

### Method 1 - PowerShell 📌 (Windows 8 and later)

1. Click the **Start Menu**, type `PowerShell`, then open it.
2. Copy and paste the code below and press **Enter**.

```
irm https://get.ntriver.org/pkeymaster | iex
```

3. That's all. Didn't work? Use Method 2.

---

### Method 2 - Download File (Windows Vista and later)

1. Download the zip file:
   - [GitHub](https://github.com/ntriver-org/PKeyMaster/archive/refs/heads/main.zip) / [Codeberg](https://codeberg.org/ntriver-org/PKeyMaster/archive/main.zip) / [Tangled](https://tangled.org/windowsaddict.ntriver.org/PKeyMaster/archive/main?format=zip)
2. Right-click on the downloaded zip file and find the option to extract.
3. Run the file named `PKeyMaster.cmd` from the extracted folder.
4. That's all.

---

**Latest version**: 0.4  
**Release date**: 06-October-2026  
**Git Mirrors**:  [GitHub](https://github.com/ntriver-org/PKeyMaster) / [Codeberg](https://codeberg.org/ntriver-org/PKeyMaster) / [Tangled](https://tangled.org/windowsaddict.ntriver.org/PKeyMaster)

---

<p align="center"><img src="https://ntriver.org/img/pkeymaster.png" alt="PKeyMaster Keychecker"></p>

---

## Features

- **Key Validation**: Validates Microsoft product keys (Windows, Office, VS, etc) from Windows 95 era to the latest releases.
- **PKeyConfigsMap**: A large collection of PKeyConfigs and a smart map to quickly search keys.
- **Key Certification**: Verifies key certification status via `SLCertifyProduct` API.
- **Key Activation**: Activates keys using `SLActivateProduct` API.
- **Redeem Status**: Checks redeem key status using `OLSC` API.
- **MAK Count**: Retrieves remaining MAK activation count.
- **Installation ID (IID)**: Generates IID using `PidGenX.dll`.
- **Confirmation ID (CID)**: Retrieves CID via the Batch API, with fallback to the Visual API.
- **Phone Activation (CID)**: Retrieves and deposits CID for eligible products.
- **PKeyConfig Reader**: Reads and exports PKeyConfig data to CSV.
- **Key Scanning**: Finds product keys in text and binary files.
- **Digital Product ID Scanning**: Detects and reads Digital Product ID blobs in files.
- **Key Retrieval**: Retrieves Windows and Office keys from the trusted store, registry, and MSDM (BIOS/UEFI).
- **Batch Processing**: Supports bulk validation of keys and IIDs.
- **Logging**: Provides detailed logs and CSV exports.
- **Open Source**: Fully open source and built with PowerShell scripts.

---

> [!TIP]
> - Some ISPs/DNS block access to our domains. You can bypass this by enabling [DNS-over-HTTPS (DoH)](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/encrypted-dns-browsers/) in your browser.  
> - **Having trouble**❓Visit our [**troubleshooting page**](https://ntriver.org/troubleshoot) or raise an issue on [GitHub](https://github.com/ntriver-org/PKeyMaster/issues).

---

[Screenshots](https://ntriver.org/pkeymaster#screenshots)  
[Documentation](https://ntriver.org/pkeymaster/key-checker)

[![Discord](https://img.shields.io/badge/Discord-Chat%20with%20us-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/476fzQ3mV3)

---

<p align="center">
  <strong>Homepage:</strong> <a href="https://ntriver.org/">https://ntriver.org/</a>
</p>

<p align="center">
  Made with Love ❤️
</p>
