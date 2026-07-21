# Triage prompt

Classify findings P0/P1/P2/skip with exploitability and impact. Do not re-read full codebase unless needed.
Return JSON array of { filePath, vulnSlug, title, priority, exploitability, impact, reasoning }.
