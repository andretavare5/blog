---
title: "Decrypting and Hunting PrivateLoader"
date: "2022-06-06T00:00:00+00:00"
lastmod: "2026-09-15T00:00:00+01:00"
description: "Building a PrivateLoader string decryptor and YARA rule from a stack-based XOR pattern."
summary: "Building a PrivateLoader string decryptor and YARA rule from a stack-based XOR pattern."
format: "Technical walkthrough"
tags: ["privateloader", "malware", "loader", "reversing", "yara", "windows"]
showToc: true
ShowReadingTime: true
aliases:
  - /blog/2022/06/06/hunting-privateloader-pay-per-install-service/
thumbnail:
  image: "images/research/hunting-privateloader-pay-per-install-service.webp"
  alt: "Two memory stacks combining to unlock hidden data inspected through a magnifying glass"
---

PrivateLoader is a Windows loader used by a pay-per-install malware distribution service. [First observed in early 2021](https://intel471.com/blog/privateloader-malware), it was distributed through websites offering cracked software and delivered payloads including information stealers, banking trojans, other loaders, and ransomware.

This walkthrough records my analysis of a 2022 sample. The goal was to recover its encrypted strings and turn the decryption pattern into a detection rule.

## Key takeaways

- PrivateLoader builds encrypted strings and their XOR keys on the stack before decoding them at runtime.
- A Capstone-based script recovers strings that help explain the sample's behavior and infrastructure.
- A YARA rule returned over 1,000 samples in a one-year VirusTotal retrohunt. Manual review found no false positives in the inspected subset; its size was not recorded, so this is not a measured false-positive rate.

## Searching for strings

Here's a [sample](https://tria.ge/220430-z8fbmaagb9) analyzed by [Zscaler](https://www.zscaler.com/blogs/security-research/peeking-privateloader) in April 2022:

`aa2c0a9e34f9fa4cbf1780d757cc84f32a8bd005142012e91a6888167f80f4d5`

Opening the sample in [Ghidra](https://ghidra-sre.org/) and following the code from its entry point led me to the function at `0x406360`. It calls `LoadLibraryA`, but constructs the `lpLibFileName` argument on the stack at runtime. Both the encrypted bytes and the XOR key are loaded onto the stack, then combined to recover the library name. The same pattern appears elsewhere in the function:

```nasm
LEA       EAX=>local_50,[ESP + 0x10]
MOV       dword ptr [ESP + local_50[0]],0x84038676
MOV       dword ptr [ESP + local_50[4]],0xeb71eb3c
MOV       dword ptr [ESP + local_50[8]],0x36fb7b30
MOV       dword ptr [ESP + local_50[12]],0xab7d1f0c
MOVAPS    XMM1,xmmword ptr [ESP + local_50[0]]
MOV       dword ptr [ESP + local_30[0]],0xea71e31d
MOV       dword ptr [ESP + local_30[4]],0xd9428759
MOV       dword ptr [ESP + local_30[8]],0x5a971f1e
MOV       dword ptr [ESP + local_30[12]],0xab7d1f0c
PXOR      XMM1,xmmword ptr [ESP + local_30[0]] ; kernel32.dll
PUSH      EAX  ; LPCSTR lpLibFileName for LoadLibraryA
MOVAPS    xmmword ptr [ESP + local_50[0]],XMM1
CALL      ESI=>KERNEL32.DLL::LoadLibraryA
```

Applying XOR to the encrypted bytes and the key produces `kernel32.dll`.

## Decrypting the strings

To make the analysis easier, I built a string decryptor using the [Capstone](https://www.capstone-engine.org/) disassembly framework. Some trial and error was needed to turn the observed pattern into the script below.

[Open the string decryptor on GitHub Gist](https://gist.github.com/andretavare5/66ec413cdb4c7c39d35c22d38c7067a8).

{{< gist andretavare5 66ec413cdb4c7c39d35c22d38c7067a8 >}}

Running it against the sample produced the following strings. Network indicators are defanged here and belong to this historical sample.

```text
0x4003ee GetCurrentProcess
0x400469 CreateThread
0x4004ba CreateFileA
0x400506 Sleep
0x400572 SetPriorityClass
0x4005ec Shell32.dll
0x400657 SHGetFolderPathA
0x40083b null
0x401078 rb
0x40157c hxxp://212[.]193[.]30[.]45/proxies.txt
0x401795 :1080
0x401839 \n
0x401f2d :1080
0x401fd1 :
0x4026ce .
0x4028ac .
0x402972 .
0x402a34 .
0x4032ad hxxp://45[.]144[.]225[.]57/server.txt
0x4033c0 HOST:
0x40346e :
0x403760 pastebin[.]com/raw/A7dSG1te
0x403965 HOST:
0x403b93 hxxp://wfsdragon[.]ru/api/setStats.php
0x403dcd HOST:
0x403f84 :
0x4040ae 2[.]56[.]59[.]42
0x404350 /base/api/statistics.php
0x404439 URL:
0x4044b6 :
0x404a5e https://
0x404ad8 .tmp
0x404bf6 \
0x4053e9 kernel32.dll
0x40544a WINHTTP.dll
0x4054a5 wininet.dll
0x406616 WinHttpConnect
0x406682 WinHttpOpenRequest
0x40671a WinHttpQueryDataAvailable
0x4067b2 WinHttpSendRequest
0x40684a WinHttpReceiveResponse
0x4068e2 WinHttpQueryHeaders
0x406956 WinHttpOpen
0x4069b5 WinHttpReadData
0x406a20 WinHttpCloseHandle
0x406b09 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
0x407402 http://
0x4074ab /
0x407582 ?
0x40851a HEAD
0x408fa8 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
0x4091f0 wininet.dll
0x40925b InternetSetOptionA
0x4092ef HttpOpenRequestA
0x40938d InternetConnectA
0x409421 InternetOpenUrlA
0x40949e InternetOpenA
0x4094f2 HttpQueryInfoA
0x409567 InternetQueryOptionA
0x4095fb HttpSendRequestA
0x409694 InternetReadFile
0x409737 InternetCloseHandle
0x4097ad Kernel32.dll
0x409801 HeapAlloc
0x409852 HeapFree
0x4098a3 GetProcessHeap
0x4098f3 CharNextA
0x409938 User32.dll
0x409994 GetLastError
0x4099e5 CreateFileA
0x409a36 WriteFile
0x409a87 CloseHandle
```

The recovered API names and network indicators give us more context for returning to Ghidra and examining the sample's capabilities. They describe the analyzed build, rather than every PrivateLoader version.

## Detecting and hunting the malware

This string-decryption pattern gives us a basis for a [YARA](https://github.com/VirusTotal/yara) rule. To narrow the matches, the rule also checks plaintext Unicode strings [used in C2 communication](https://www.zscaler.com/blogs/security-research/peeking-privateloader) and a few additional conditions.

[Open the original YARA rule revision on GitHub Gist](https://gist.github.com/andretavare5/9d8eb659946ff509d9987c9be4031bb6/2aba78c871da34dcf3a2c2d5171f593299c0410e).

{{< gist andretavare5 "9d8eb659946ff509d9987c9be4031bb6/2aba78c871da34dcf3a2c2d5171f593299c0410e" >}}

The rule returned over 1,000 samples in a VirusTotal retrohunt spanning one year. I found no false positives among the matches I manually inspected, but did not record the size of that subset. The result was a useful starting point for hunting PrivateLoader, rather than a complete validation of detection coverage or specificity.

The decryptor and rule above preserve the original research artifacts. Their applicability to later builds needs separate validation.
