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

PrivateLoader is a malware loader from a pay-per-install malware distribution service, that has been used to distribute info stealers, banking trojans, other loaders, and even ransomware, on machines running windows. [First seen in early 2021](https://intel471.com/blog/privateloader-malware) being hosted on websites that claim to provide cracked software, the customers of the service are able to selectively deliver malware to victims based on location, financial activity, environment, and specific software installed.

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

This uncommon string decryption technique can be leveraged to write a [Yara](https://github.com/VirusTotal/yara) rule for detection and hunting purposes. To reduce the number of false positives and increase the rule performance, we can add some plaintext unicode strings [used on the C2 communication](https://www.zscaler.com/blogs/security-research/peeking-privateloader) and a few minor conditions. Here's the rule: 

<br />
{{< gist andretavare5 9d8eb659946ff509d9987c9be4031bb6 >}}

After running this rule on VirusTotal retro hunting, I got over 1k samples on a 1 year timeframe. By manually analyzing some of the matches, I couldn't find any false positives. As a first attempt of hunting and detecting PrivateLoader, this rule seems to yield good results.

## Decrypting The Strings

Now, to faster analyze the malware and better understand its behavior, we should build a string decryptor to help us on our reversing efforts and better document the code. With the help of [Capstone](https://www.capstone-engine.org/) disassembly framework, and some trial and error, here's the script:

<br />
{{< gist andretavare5 66ec413cdb4c7c39d35c22d38c7067a8 >}}

After running it against the sample we are analyzing, we get the following strings:

```
0x4013ee GetCurrentProcess
0x401469 CreateThread
0x4014ba CreateFileA
0x401506 Sleep
0x401572 SetPriorityClass
0x4015ec Shell32.dll
0x401657 SHGetFolderPathA
0x40183b null
0x402078 rb
0x4025b0 http://212.193.30.45/proxies.txt
0x402795 :1080
0x402839 \n
0x402f2d :1080
0x402fd1 :
0x4036ce .
0x4038ac .
0x403972 .
0x403a34 .
0x4042ad http://45.144.225.57/server.txt
0x4043c0 HOST:
0x40446e :
0x404760 pastebin.com/raw/A7dSG1te
0x4048a3 HOST:
0x404965 HOST:
0x404b93 http://wfsdragon.ru/api/setStats.php
0x404dcd HOST:
0x404f84 :
0x4050ae 2.56.59.42
0x405439 URL:
0x405a5e https://
0x405ad8 .tmp
0x405bf6 \
0x4063e9 kernel32.dll
0x40644a WINHTTP.dll
0x4064a5 wininet.dll
0x407616 WinHttpConnect
0x407682 WinHttpOpenRequest
0x40771a WinHttpQueryDataAvailable
0x4077b2 WinHttpSendRequest
0x40784a WinHttpReceiveResponse
0x4078e2 WinHttpQueryHeaders
0x407956 WinHttpOpen
0x4079b5 WinHttpReadData
0x407a20 WinHttpCloseHandle
0x407b09 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
0x408402 http://
0x4084ab /
0x408582 ?
0x40951a HEAD
0x409fa8 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
0x40a1f0 wininet.dll
0x40a25b InternetSetOptionA
0x40a2ef HttpOpenRequestA
0x40a38d InternetConnectA
0x40a421 InternetOpenUrlA
0x40a49e InternetOpenA
0x40a4f2 HttpQueryInfoA
0x40a567 InternetQueryOptionA
0x40a5fb HttpSendRequestA
0x40a694 InternetReadFile
0x40a737 InternetCloseHandle
0x40a7ad Kernel32.dll
0x40a801 HeapAlloc
0x40a852 HeapFree
0x40a8a3 GetProcessHeap
0x40a8f3 CharNextA
0x40a938 User32.dll
0x40a994 GetLastError
0x40a9e5 CreateFileA
0x40aa36 WriteFile
0x40aa87 CloseHandle
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


