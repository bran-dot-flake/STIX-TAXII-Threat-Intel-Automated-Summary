# Executive summary comparison

Both versions use the same frozen November 2–9, 2026 source evidence and reporting window. The draft-generation code contains no example briefing or fixed prose template; the repository review registry stores approved text as a source-bound audit record.

## Before — 225 words, three paragraphs

**Cloud Access Abuse and Exploit Scanning**

Access itself was a commodity in two reports published this week, although they described separate operations. Mandiant’s account of LLMJacking described intruders using enterprise access to language models across several providers. The financial consequence can arrive quickly: fraudulent cloud charges may rise sharply within hours, rather than building through the slower consumption associated with cryptojacking. The incidents described occurred during 2026; their publication this week does not place all of that activity inside this reporting window.

The distinction between reporting and event dates also matters for XCPE: Google’s account placed the disruption in the week before publication. The backdoor had drawn more than 1.3 million set-top boxes into a botnet before Google and industry partners dismantled it. Its monetization extended beyond the original operator: access was sold to criminal affiliates, and their malware modules were loaded onto infected devices.

The SSH reporting offered a narrower signal: SANS saw increased attempts against Sshole in its Cowrie honeypots. That is evidence of activity in a limited observation set, rather than a measure of global attack frequency or proof that intruders succeeded. Long passwords stood out from the usual brute-force traffic, but the sensors recorded only the first 255 characters. Taken together, these accounts distinguish documented misuse of existing access, a reported botnet disruption, and a qualified signal of exploit attempts; they do not establish a shared campaign.

## After — 114 words, two paragraphs

**LLM Hijacking Can Drive Rapid Cloud Bills**

Enterprise access to language models can become a fast-moving financial liability when it is hijacked. Mandiant described multiple LLMJacking incidents across cloud and model providers, with fraudulent charges capable of climbing sharply within hours. That speed distinguishes the abuse from the more gradual resource consumption of cryptojacking. For cloud teams, unexpected model-related charges are a concrete reason to investigate possible misuse of enterprise access.

Google and industry partners also dismantled the XCPE backdoor, which had enrolled more than 1.3 million set-top boxes. The operator sold access to criminal affiliates and loaded their malware modules onto infected devices. The disruption targeted a business that turned control of those devices into a service for criminal affiliates.

The lead now explains rapid financial exposure and a conditional reason to investigate unexpected model-related charges. The secondary paragraph explains XCPE’s scale and affiliate business; SSH observations stay in the radar. Source dates, visibility limits and exact chronology remain in the supporting evidence instead of becoming the article’s main subject. No shared campaign, new incident count or successful SSH compromise is claimed.

## Generation and review

Two sentence/citation-structured trials repeated notes or misassigned claims. Separating prose drafting from sentence-level citation annotation produced a complete 168-word, two-paragraph local Ollama proposal (407 output tokens, normal stop). That raw draft still included unsupported impact-assessment/law-enforcement language, generic vigilance and weak radar items; it was **not accepted unchanged**. The final text above was edited, annotated sentence by sentence and checked against exact source spans under `ollama-edited-reviewed`.

Raw proposals remain private on the VM under `work/final-layout/`; they are not public examples or publication inputs. The unchanged evidence digest is `177fc8507c63a3e2a89c70916e67fce73f3126a3b1c5911701d562d421b50d0d`. Original source links and rights remain in the published evidence. New free prose still requires explicit source-bound review; citation-shaped output alone cannot pass.


## Rendered layout comparison

Measured with the same source dataset, closed disclosures and 1,050-pixel viewport height. No horizontal overflow at any width.

| Viewport width | Before page height | After page height | Before brief height | After brief height |
| --- | --- | --- | --- | --- |
| 390 px | 3112 px | 2670 px | 1213 px | 891 px |
| 768 px | 2035 px | 1738 px | 785 px | 530 px |
| 1440 px | 1948 px | 1663 px | 774 px | 515 px |

The article now precedes its supporting evidence and the radar strip, removing mismatched column heights. Radar items sit in three columns on desktop and stack on phones. The header timestamp and visible chart table are gone; a two-link footer opens an accessible source/license dialog. Detailed catalog values and chronology remain in public JSON and technical evidence.
