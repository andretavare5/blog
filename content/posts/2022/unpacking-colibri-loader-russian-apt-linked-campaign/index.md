---
title: "Unpacking Colibri Loader: A Russian APT-linked Campaign"
date: "2022-11-30T00:00:00+00:00"
lastmod: "2026-09-15T00:00:00+01:00"
description: "A Colibri Loader unpacking walkthrough covering anti-analysis techniques, string decryption, and YARA detection."
summary: "A Colibri Loader unpacking walkthrough covering anti-analysis techniques, string decryption, and YARA detection."
format: "Research article"
tags: ["colibriloader", "malware", "loader", "yara", "windows", "bitsight", "reversing"]
sourceURL: "https://www.bitsight.com/blog/unpacking-colibri-loader-russian-apt-linked-campaign"
thumbnail:
  image: "images/research/unpacking-colibri-loader-russian-apt-linked-campaign.webp"
  alt: "A bird escaping a cage beside layers opening to reveal a circuit core"
---

Colibri Loader is a malware loader. This November 2022 investigation walks through unpacking a campaign sample, handling anti-analysis techniques, and recovering strings that expose the malware's behavior and infrastructure.

The analysis includes patching opaque predicates that confuse disassembly and using an existing IDA script to decrypt strings. It credits the researchers whose tooling supported the investigation and publishes YARA rules for detection.

The campaign association in the original title belongs to that publication's evidence and context. The walkthrough is most useful as a record of the analysis method; it should not be read as a broader attribution claim about all Colibri Loader activity.

[Read the original article at Bitsight](https://www.bitsight.com/blog/unpacking-colibri-loader-russian-apt-linked-campaign)
