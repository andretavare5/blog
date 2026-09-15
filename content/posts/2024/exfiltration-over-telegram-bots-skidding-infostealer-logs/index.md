---
title: "Exfiltration over Telegram Bots: Skidding Infostealer Logs"
date: "2024-10-16T00:00:00+00:00"
lastmod: "2026-09-15T00:00:00+01:00"
description: "An investigation of Telegram bot exfiltration, infostealer log formats, and the visibility those records provide."
summary: "An investigation of Telegram bot exfiltration, infostealer log formats, and the visibility those records provide."
format: "Research article"
tags: ["telegram", "malware", "infostealer", "windows", "agenttesla", "snakekeylogger", "vipkeylogger", "bitsight"]
featured: true
featuredOrder: 3
focus: "Exfiltration analysis · Data processing · Threat intelligence"
sourceURL: "https://www.bitsight.com/blog/exfiltration-over-telegram-bots-skidding-infostealer-logs"
thumbnail:
  image: "images/research/exfiltration-over-telegram-bots-skidding-infostealer-logs.webp"
  alt: "Credential records flowing from a laptop to a Telegram paper-plane symbol"
---

Some infostealers use Telegram's Bot API to send stolen credentials and system information to their operators. This October 2024 article examines logs obtained directly from those bots and the visibility they provide into the infostealer ecosystem.

The published team dataset contained about five million logs from approximately 1,800 bots, with parsers covering 27 infostealer families. Collection began in October 2024, while timestamps in the records reached back to 2020 and were mostly from 2022 onward.

These are log records, not a count of unique victims. The findings describe the collected bots and available records; they do not measure the entire infostealer population.

[Read the original article at Bitsight](https://www.bitsight.com/blog/exfiltration-over-telegram-bots-skidding-infostealer-logs)
