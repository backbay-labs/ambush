"""
Offensive domain -- Red teaming modules for Hellcat.

Contains hellcat's offensive-specific subsystems that were separated from the
shared kernel core to allow merging with defensive (huntronomer) code:

    operators/      Security operator adapters (recon, injection, XSS, auth, etc.)
    operator_base   SecurityOperator base class
    operator_registry  Operator name -> class registry
    target_graph/   SQLite-backed attack surface graph
    recon/          9-phase structured recon pipeline
    opsec/          Noise monitor, stealth budget, circuit breaker
    evasion/        WAF bypass, rate-limit evasion loop
    proof/          L1-L4 evidence gate pipeline
    strikecell/     Docker-isolated execution environments
    continuous/     Engagement watcher and surface differ
    tools/          External security tool wrappers (nmap, nuclei, sqlmap, etc.)
    learning/       Cross-engagement AttackPatternDB
    knowledge/      VulnKnowledgeBase and seed data
"""
