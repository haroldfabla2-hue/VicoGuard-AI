# 📚 Resumen de Papers de Ciberseguridad e Inteligencia Artificial Agéntica

Este documento recopila las introducciones y resúmenes de los papers agregados a la documentación del proyecto para incorporarlos a la arquitectura de **VicoGuard AI**.

## 1. 2602.05868v1.pdf
- **Páginas totales:** 8
- **Ruta local:** [2602.05868v1.pdf](file:///d:/Proyectos personales/Hackaton Flit/docs_pdf/2602.05868v1.pdf)

### 📝 Fragmento de Introducción / Abstract:

```text
Persistent Human Feedback, LLMs, and Static
Analyzers for Secure Code Generation and
Vulnerability Detection
Ehsan Firouzi
Technische Universität Clausthal
Germany
Mohammad Ghafari
Technische Universität Clausthal
Germany
Abstract—Existing literature heavily relies on static analysis
tools to evaluate LLMs for secure code generation and vulnera-
bility detection. We reviewed 1,080 LLM-generated code samples,
built a human-validated ground-truth, and compared the outputs
of two widely used static security tools, CodeQL and Semgrep,
against this corpus. While 61% of the samples were genuinely
secure, Semgrep and CodeQL classified 60% and 80% as
secure, respectively. Despite the apparent agreement in aggregate
statistics, per-sample analysis reveals substantial discrepancies:
only 65% of Semgrep’s and 61% of CodeQL’s reports correctly
matched the ground truth. These results question the reliability
of static analysis tools as sole evaluators of code security and
underscore the need for expert feedback. Building on this insight,
we propose a conceptual framework that persistently stores
human feedback in a dynamic retrieval-augmented generation
pipeline, enabling LLMs to reuse past feedback for secure code
generation and vulnerability detection.
Index Terms—LLMs for security, human-centered security,
secure code generation, vulnerability detection, static analysis
I. INTRODUCTION
Large language models ( LLMs) have turned into an impor-
tant part of everyday software development. The 2025 Stack
Overflow Developer Survey reports that 82% of developers
used OpenAI’s GPT models in their work over the last year [1].
This widespread adoption highlights both the promise and the
risks of relying on LLMs for code generation.
Despite their practical benefits, LLMs can generate insecure
code and configurations even when explicitly instructed to
produce secure solutions [2], undermining trust in their results.
Static analysis tools can effectively surface potential vulner-
abilities; however, research shows that they may exhibit high
false-positive rates [3] and can be difficult to act upon without
additional context. Recent studies also highlight LLMs’ ability
to identify certain classes of vulnerabilities [4]–[6].
In this paper, we first survey publications from top-tier
software engineering venues in 2025 to characterize current
research on the use of LLMs for secure code generation
and vulnerability detection. We examine how the literature
evaluates generated code, including the benchmarks used,
target programming languages, and evaluation practices. Our
analysis shows that existing benchmarks predominantly focus
```

---

## 2. 2508.04482v1.pdf
- **Páginas totales:** 36
- **Ruta local:** [2508.04482v1.pdf](file:///d:/Proyectos personales/Hackaton Flit/docs_pdf/2508.04482v1.pdf)

### 📝 Fragmento de Introducción / Abstract:

```text
OS Agents: A Survey on MLLM-based Agents
for General Computing Devices Use
Xueyu Hu1, †, Tao Xiong1, ‡, Biao Yi1, ‡, Zishu Wei1, ‡
Ruixuan Xiao1, Yurun Chen1, Jiasheng Ye2, Meiling Tao3, Xiangxin Zhou4, 5, Ziyu Zhao1,
Yuhuai Li1, Shengze Xu6, Shenzhi Wang7, Xinchen Xu1, Shuofei Qiao1, Zhaokai Wang8
Kun Kuang1, Tieyong Zeng6, Liang Wang4, 5, Jiwei Li1, Yuchen Eleanor Jiang3,
Wangchunshu Zhou3, Guoyin Wang9, Keting Yin1, Zhou Zhao1,
Hongxia Yang10, Fan Wu8, Shengyu Zhang1, *, Fei Wu1
1Zhejiang University 2Fudan University 3OPPO AI Center
4University of Chinese Academy of Sciences
5Institute of Automation, Chinese Academy of Sciences
6The Chinese University of Hong Kong 7Tsinghua University 8Shanghai Jiao Tong University
901.AI 10The Hong Kong Polytechnic University
{huxueyu, sy_zhang}@zju.edu.cn
https://os-agent-survey.github.io/
https://aclanthology.org/2025.acl-long.369/
Abstract
The dream to create AI assistants as capable and versatile as the fictional J.A.R.V.I.S
from Iron Man has long captivated imaginations. With the evolution of (multi-
modal) large language models ((M)LLMs), this dream is closer to reality, as
(M)LLM-based Agents using computing devices (e.g., computers and mobile
phones) by operating within the environments and interfaces (e.g., Graphical User
Interface (GUI)) provided by operating systems (OS) to automate tasks have signif-
icantly advanced. This paper presents a comprehensive survey of these advanced
agents, designated as OS Agents. We begin by elucidating the fundamentals of OS
Agents, exploring their key components including the environment, observation
space, and action space, and outlining essential capabilities such as understanding,
planning, and grounding. We then examine methodologies for constructing OS
Agents, focusing on domain-specific foundation models and agent frameworks.
A detailed review of evaluation protocols and benchmarks highlights how OS
Agents are assessed across diverse tasks. Finally, we discuss current challenges
and identify promising directions for future research, including safety and privacy,
personalization and self-evolution. This survey aims to consolidate the state of OS
Agents research, providing insights to guide both academic inquiry and industrial
development. An open-source GitHub repository is maintained as a dynamic re-
source to foster further innovation in this field. We present a 9-page version of our
work, accepted by ACL 2025, to provide a concise overview to the domain.
†Projsssect Lead, ‡Core Contributor, ∗Corresponding Author
arXiv:2508.04482v1  [cs.AI]  6 Aug 2025
Contents
1
Introduction
3
2
Fundamental of OS Agents
4
2.1
Key Component . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
4
2.2
```

---

## 3. 2606.31498v1.pdf
- **Páginas totales:** 7
- **Ruta local:** [2606.31498v1.pdf](file:///d:/Proyectos personales/Hackaton Flit/docs_pdf/2606.31498v1.pdf)

### 📝 Fragmento de Introducción / Abstract:

```text
Governance Gaps in Agent Interoperability
Protocols:
What MCP, A2A, and ACP Cannot Express
Dr. Richard Kang
DoiT International
richard@doit.com
Yudho Diponegoro
Abstract—Agent interoperability protocols—MCP, A2A, ACP,
ANP, and ERC-8004—have rapidly matured to enable identity,
capability discovery, tool access, and message exchange between
autonomous agents. However, as enterprises deploy heteroge-
neous agent fleets that must make collective decisions under
governance constraints, a question arises: can these protocols
support governed agent communities, or only task-oriented
coordination? We present a systematic gap analysis applying a
six-dimension governance requirements taxonomy—membership,
deliberation, voting, dissent preservation, human escalation, and
audit/replay—derived from organizational theory, multi-agent
systems literature, and enterprise governance standards. We
analyze each protocol’s specification against this taxonomy,
classifying capabilities as Supported, Partial, or Absent. The
resulting gap matrix reveals that voting and dissent preservation
are universally absent across all five protocols, deliberation is
absent or at most partial, and no protocol encodes the full
set of primitives required for governed agent communities.
We distinguish extensible gaps (addressable through protocol
extension mechanisms) from structural gaps (requiring a new
architectural layer) and assess time-sensitivity based on observed
protocol evolution velocity. The analysis establishes that agent
community governance constitutes a missing architectural layer
above current interoperability standards—not a missing feature
within them.
Index Terms—agent interoperability, governance, multi-agent
systems, MCP, A2A, protocol analysis, agent communities, delib-
eration
I. INTRODUCTION
The proliferation of LLM-based agents in enterprise en-
vironments has driven rapid development of interoperability
protocols. The Model Context Protocol (MCP) [1] enables
agents to access tools and data sources. The Agent-to-Agent
protocol (A2A) [2] standardizes discovery and delegation be-
tween agents. The Agent Communication Protocol (ACP) [3]
formalizes structured message exchange. The Agent Network
Protocol (ANP) [4] provides graph-based routing with de-
centralized identity. ERC-8004 [5] encodes on-chain identity,
reputation, and validation registries.
Together, these protocols address a coherent set of coordina-
tion concerns: identity, capability declaration, discovery, tool
access, message passing, and reputation. Enterprises deploying
agent fleets—AWS reports AgentCore customers scaling to
```

---

## 4. 2405.17238v3.pdf
- **Páginas totales:** 24
- **Ruta local:** [2405.17238v3.pdf](file:///d:/Proyectos personales/Hackaton Flit/docs_pdf/2405.17238v3.pdf)

### 📝 Fragmento de Introducción / Abstract:

```text
Published as a conference paper at ICLR 2025
IRIS: LLM-ASSISTED STATIC ANALYSIS FOR
DETECTING SECURITY VULNERABILITIES
Ziyang Li
University of Pennsylvania
liby99@cis.upenn.edu
Saikat Dutta
Cornell University
saikatd@cornell.edu
Mayur Naik
University of Pennsylvania
mhnaik@cis.upenn.edu
ABSTRACT
Software is prone to security vulnerabilities. Program analysis tools to detect
them have limited effectiveness in practice due to their reliance on human labeled
specifications. Large language models (or LLMs) have shown impressive code
generation capabilities but they cannot do complex reasoning over code to detect
such vulnerabilities especially since this task requires whole-repository analysis.
We propose IRIS, a neuro-symbolic approach that systematically combines LLMs
with static analysis to perform whole-repository reasoning for security vulnera-
bility detection. Specifically, IRIS leverages LLMs to infer taint specifications
and perform contextual analysis, alleviating needs for human specifications and
inspection. For evaluation, we curate a new dataset, CWE-Bench-Java, compris-
ing 120 manually validated security vulnerabilities in real-world Java projects. A
state-of-the-art static analysis tool CodeQL detects only 27 of these vulnerabilities
whereas IRIS with GPT-4 detects 55 (+28) and improves upon CodeQL’s average
false discovery rate by 5% points. Furthermore, IRIS identifies 4 previously un-
known vulnerabilities which cannot be found by existing tools. IRIS is available
publicly at https://github.com/iris-sast/iris.
1
INTRODUCTION
Security vulnerabilities pose a major threat to the safety of software applications and its users. In
2023 alone, more than 29,000 CVEs were reported—almost 4000 higher than in 2022 (CVE Trends).
Detecting vulnerabilities is extremely challenging despite advances in techniques to uncover them.
A promising such technique called static taint analysis is widely used in popular tools such as GitHub
CodeQL (Avgustinov et al., 2016), Facebook Infer (FB Infer), Checker Framework (Checker Frame-
work), and Snyk Code (Snyk.io). These tools, however, face several challenges that greatly limit
their effectiveness and accessibility in practice.
CWE-22: Path-Traversal
Improper Limitation of a Pathname to a
Restricted Directory: The product uses
external input to construct pathname…
src/main/
README.md
Spark.java
Service.java
pathInfo = request.getPathInfo();
AbstractResourceHandler.java
ClassPathResource.java
is = clazz.getResourceAsStream(path);
```

---

## 5. 2502.07049v2.pdf
- **Páginas totales:** 33
- **Ruta local:** [2502.07049v2.pdf](file:///d:/Proyectos personales/Hackaton Flit/docs_pdf/2502.07049v2.pdf)

### 📝 Fragmento de Introducción / Abstract:

```text
LLMs in Software Security: A Survey of Vulnerability
Detection Techniques and Insights
ZE SHENG, Texas A&M University, USA
ZHICHENG CHEN, Texas A&M University, USA
SHUNING GU, Texas A&M University, USA
HEQING HUANG, City University of Hong Kong, China
GUOFEI GU, Texas A&M University, USA
JEFF HUANG, Texas A&M University, USA
Large Language Models (LLMs) are emerging as transformative tools for software vulnerability detection.
Traditional methods, including static and dynamic analysis, face limitations in efficiency, false-positive rates,
and scalability with modern software complexity. Through code structure analysis, pattern identification, and
repair suggestion generation, LLMs demonstrate a novel approach to vulnerability mitigation.
This survey examines LLMs in vulnerability detection, analyzing problem formulation, model selection,
application methodologies, datasets, and evaluation metrics. We investigate current research challenges,
emphasizing cross-language detection, multimodal integration, and repository-level analysis. Based on our
findings, we propose solutions addressing dataset scalability, model interpretability, and low-resource scenarios.
Our contributions include: (1) a systematic analysis of LLM applications in vulnerability detection; (2) a
unified framework examining patterns and variations across studies; and (3) identification of key challenges
and research directions. This work advances the understanding of LLM-based vulnerability detection. The
latest findings are maintained at https://github.com/OwenSanzas/LLM-For-Vulnerability-Detection
Additional Key Words and Phrases: Large Language Models, Vulnerability Detection, Cybersecurity
ACM Reference Format:
Ze Sheng, Zhicheng Chen, Shuning Gu, Heqing Huang, Guofei Gu, and Jeff Huang. 2025. LLMs in Software
Security: A Survey of Vulnerability Detection Techniques and Insights. 1, 1 (February 2025), 33 pages.
https://doi.org/10.1145/nnnnnnn.nnnnnnn
1
INTRODUCTION
Vulnerability detection plays an important part in the design and maintenance of modern software.
Statistical evidence indicates that approximately 70% of security vulnerabilities originate from
defects in the software development process [4]. According to the metrics provided by Common
Vulnerabilities and Exposures Numbering Authorities (CNAs), a growth is witnessed that in the past
5 years, about 120,000 CVEs have been discovered and reported [20]. According to FBI’s cybercrime
report shown in Figure 1, the period from 2018 to 2023 suffers from a large amount of cybersecurity
crimes and complaints. A recent example is the CrowdStrike incident in July 2024 [110], where
a faulty software update caused widespread system crashes across critical infrastructure sectors
including healthcare, transportation, and finance. Therefore, enhanced focus and investment in
vulnerability detection technology is in demand.
State-of-the-art vulnerability detection approaches/tools can be broadly classified into static
analysis and dynamic analysis [18, 76, 100, 133]. Static analysis examines source code or bytecode to
Authors’ addresses: Ze Sheng, Texas A&M University, College Station, USA, zesheng@tamu.edu; Zhicheng Chen, Texas
A&M University, College Station, USA, zhicheng@tamu.edu; Shuning Gu, Texas A&M University, College Station, USA,
shuning@tamu.edu; Heqing Huang, City University of Hong Kong, Hong Kong, China, heqhuang@cityu.edu.hk; Guofei
Gu, Texas A&M University, College Station, USA, guofei@tamu.edu; Jeff Huang, Texas A&M University, College Station,
USA, jeffhuang@tamu.edu.
2025. XXXX-XXXX/2025/2-ART $15.00
https://doi.org/10.1145/nnnnnnn.nnnnnnn
, Vol. 1, No. 1, Article . Publication date: February 2025.
arXiv:2502.07049v2  [cs.CR]  12 Feb 2025
2
Sheng et al.
```

---

