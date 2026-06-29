#!/usr/bin/env node
// Offline stub inner MCP server for the headless gate smoke.
//
// The swarm-mcp-gate proxy spawns its inner MCP server and forwards every frame
// EXCEPT a denied `tools/call`. In production that inner server is the real
// OpenKnowledge `ok mcp`; for a deterministic, network-free smoke we substitute
// this stub. It speaks just enough newline-delimited JSON-RPC to answer the
// frames the gate forwards: `initialize`, `notifications/initialized`, and any
// ALLOWED `tools/call` (a denied one never reaches us — the gate answers it).

import { createInterface } from 'node:readline'

const rl = createInterface({ input: process.stdin })

function send(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`)
}

rl.on('line', (line) => {
  const trimmed = line.trim()
  if (!trimmed) return
  let frame
  try {
    frame = JSON.parse(trimmed)
  } catch {
    return
  }
  const { id, method } = frame
  if (method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'stub-inner-mcp', version: '0.0.0' },
      },
    })
    return
  }
  if (method === 'tools/call') {
    // Only ALLOWED calls are forwarded here; echo a trivial successful result.
    send({
      jsonrpc: '2.0',
      id,
      result: { content: [{ type: 'text', text: 'ok' }], isError: false },
    })
    return
  }
  // notifications/* and anything else: nothing to answer.
})

rl.on('close', () => process.exit(0))
