---
title: "Hunting PrivateLoader: Pay-Per-Install Service"
date: 2022-06-06
slug: "hunting-privateloader-pay-per-install-service"
description: "Detection and IOCs extraction"
keywords: ["privateloader", "malware", "loader", "reversing", "yara", "windows"]
draft: false
tags: ["privateloader", "malware", "loader", "reversing", "yara", "windows"]
math: false
toc: false
---
<br />
{{< figure src="/blog/2022/06/06/andreas-brun-f1SLpsPGODo-unsplash.webp" alt="Cat hunting" link="https://unsplash.com/photos/f1SLpsPGODo" >}}

PrivateLoader is a downloader, [first seen on early 2021](https://intel471.com/blog/privateloader-malware). It's part of a pay-per-install malware distribution service available on underground forums and so it's used by multiple threat actors to distribute ransomware, information stealers, banking trojans, downloaders, and other commodity malware on windows machines. The malware payloads are selectively delivered to victims based on certain criteria such as location, financial activity, environment and specific software installed. It's delivered through websites that claim to provide cracked software.

Let's have a look at the malware and try to find a way to detect and hunt it.

## Encrypted Stack Strings

Here's a [sample](https://tria.ge/220430-z8fbmaagb9) analyzed by [Zscaler](https://www.zscaler.com/blogs/security-research/peeking-privateloader) on April 2022: 

```
aa2c0a9e34f9fa4cbf1780d757cc84f32a8bd005142012e91a6888167f80f4d5
```

Let's open it on [Ghidra](https://ghidra-sre.org/). Going into the entry point, following the code, looking for interesting functions, I quickly spot the function at `0x406360`. It's calling `LoadLibraryA` but the `lpLibFileName` parameter is built dynamically at runtime using the stack. Its seems that we found a string encryption technique. Both the string and the xor key are loaded into the stack. Looking a bit more through the function, its seems that this is the way most of the strings are loaded:

<br />
{{< figure src="/blog/2022/06/06/privateloader-stack-xor-str.webp" alt="privateloader stack xor str" >}}

After XOR the encrypted string with the key, we get `kernel32.dll`.

## Detecting The Malware

This uncommon string decryption technique can be leveraged to write a [Yara](https://github.com/VirusTotal/yara) rule for detection and hunting purposes. To reduce the number of false positives and increase the rule performance, we can add a plaintext unicode string [used on the C2 communication](https://www.zscaler.com/blogs/security-research/peeking-privateloader) and a few minor conditions. Here's the rule: 

<br />
{{< gist andretavare5 9d8eb659946ff509d9987c9be4031bb6 >}}

After running this rule on VirusTotal retro hunting, I got over 1.7k samples on a 1 year timeframe. By manually analyzing some of the matches, I couldn't find any false positives. As a first attempt of hunting and detecting PrivateLoader, this rule seems to yield good results.

## Decrypting The Strings

Now, to faster analyze the malware and better understand its behavior, we should build a string decryptor to help us on our reversing efforts and better document the code. With the help of [Capstone](https://www.capstone-engine.org/) disassembly framework, and some trial and error, here's the script:

<br />
{{< gist andretavare5 66ec413cdb4c7c39d35c22d38c7067a8 >}}

After running it against the sample we are analyzing, we get the following strings:

```
0x4003ee GetCurrentProcess
0x400469 CreateThread
0x4004ba CreateFileA
0x400506 Sleep
0x400572 SetPriorityClass
0x4005ec Shell32.dll
0x400657 SHGetFolderPathA
0x40083b null
0x401078 rb
0x40157c http://212.193.30.45/proxies.txt
0x401795 :1080
0x401839 \n
0x401f2d :1080
0x401fd1 :
0x4026ce .
0x4028ac .
0x402972 .
0x402a34 .
0x4032ad http://45.144.225.57/server.txt
0x4033c0 HOST:
0x40346e :
0x403760 pastebin.com/rawHOST:
0x403965 HOST:
0x403b93 http://wfsdragon.ru/api/setStats.php
0x403dcd HOST:
0x403f84 :
0x4040ae 2.56.59.42
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

We can now go back to Ghidra and continue our analysis, now with more context of what might be the malware's behavior. 

## Network IOCs

As a bonus, we get some network IOCs that can be used for defense and tracking purposes:

```
http://212.193.30.45/proxies.txt
http://45.144.225.57/server.txt
pastebin.com/raw/A7dSG1te
http://wfsdragon.ru/api/setStats.php
2.56.59.42
/base/api/statistics.php
```


