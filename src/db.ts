import { createClient, SupabaseClient } from '@supabase/supabase-js'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Block {
  id: string
  domain: string
  action_key: string
  method: { type: string; value: string; context?: string }
  upvote_count: number
  downvote_count: number
  last_upvoted_at: string | null
  demoted: boolean
  score?: number
}

export interface Agent {
  install_id: string
  user_id: string
  registered_at: string
}

export interface WorkflowStep {
  step_index: number
  action_name: string
  method: { type: string; value: string; context?: string }
  notes?: string | null
}

export interface Workflow {
  id: string
  domain: string
  workflow_key: string
  description: string
  steps: WorkflowStep[]
  score: number
  contributor_count: number
  last_verified_at: string | null
}

export interface WorkflowStub {
  id: string
  workflow_key: string
  description: string
  step_count: number
  score: number
  contributor_count: number
  last_verified_at: string | null
}

export interface SearchResult {
  domain: string
  query: string | null
  workflows: WorkflowStub[]
  action_keys: string[]
}

// ─── Supabase client ──────────────────────────────────────────────────────────

let client: SupabaseClient | null = null

function getClient(): SupabaseClient {
  if (!client) {
    const url = process.env.SUPABASE_URL
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY
    if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY required')
    client = createClient(url, key)
  }
  return client
}

async function rpc<T>(fn: string, args: Record<string, unknown>): Promise<T> {
  const { data, error } = await getClient().schema('hive').rpc(fn, args)
  if (error) throw error
  return data as T
}

// ─── Agents ───────────────────────────────────────────────────────────────────

export async function registerAgent(installId: string, userId: string): Promise<string> {
  return rpc<string>('register', { p_install_id: installId, p_user_id: userId })
}

export async function getAgent(userId: string): Promise<Agent | null> {
  const rows = await rpc<Agent[]>('get_agent', { p_user_id: userId })
  return rows?.[0] ?? null
}

// ─── Atomic blocks ────────────────────────────────────────────────────────────

export async function pullChain(domain: string, actionKey: string, limit = 5): Promise<Block[]> {
  return rpc<Block[]>('pull', { p_domain: domain, p_action_key: actionKey, p_limit: limit })
}

export async function contributeBlock(block: {
  id: string
  domain: string
  action_key: string
  method: object
  install_id: string
  parent?: string | null
}): Promise<{ isNew: boolean }> {
  const result = await rpc<{ is_new: boolean }>('contribute', {
    p_id:         block.id,
    p_domain:     block.domain,
    p_action_key: block.action_key,
    p_method:     block.method,
    p_install_id: block.install_id,
    p_parent:     block.parent ?? null,
  })
  return { isNew: result.is_new }
}

export async function vote(
  blockId: string,
  installId: string,
  direction: 'up' | 'down'
): Promise<number | null> {
  return rpc<number | null>('vote', {
    p_block_id:   blockId,
    p_install_id: installId,
    p_direction:  direction,
  })
}

export async function status(domain: string, actionKey?: string): Promise<Record<string, unknown>[]> {
  return rpc<Record<string, unknown>[]>('status', {
    p_domain:     domain,
    p_action_key: actionKey ?? null,
  })
}

// ─── Workflows ────────────────────────────────────────────────────────────────

export async function contributeWorkflow(workflow: {
  id: string
  domain: string
  workflow_key: string
  description: string
  steps: Array<{ step_index: number; action_name: string; method: object; notes?: string }>
  install_id: string
}): Promise<{ workflowId: string; isNew: boolean }> {
  const result = await rpc<{ workflow_id: string; is_new: boolean }>('contribute_workflow', {
    p_id:           workflow.id,
    p_domain:       workflow.domain,
    p_workflow_key: workflow.workflow_key,
    p_description:  workflow.description,
    p_steps:        workflow.steps,
    p_install_id:   workflow.install_id,
  })
  return { workflowId: result.workflow_id, isNew: result.is_new }
}

export async function pullWorkflow(domain: string, workflowKey: string): Promise<Workflow | null> {
  return rpc<Workflow | null>('pull_workflow', {
    p_domain:       domain,
    p_workflow_key: workflowKey,
  })
}

export async function searchKnowledge(domain: string, query?: string): Promise<SearchResult> {
  return rpc<SearchResult>('search', {
    p_domain: domain,
    p_query:  query ?? null,
  })
}

export async function voteWorkflow(
  workflowId: string,
  installId: string,
  direction: 'up' | 'down'
): Promise<number | null> {
  return rpc<number | null>('vote_workflow', {
    p_workflow_id: workflowId,
    p_install_id:  installId,
    p_direction:   direction,
  })
}
