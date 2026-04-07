import { createClient, SupabaseClient } from '@supabase/supabase-js'

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

export async function registerAgent(installId: string, userId: string): Promise<string> {
  return rpc<string>('register', { p_install_id: installId, p_user_id: userId })
}

export async function getAgent(userId: string): Promise<Agent | null> {
  const rows = await rpc<Agent[]>('get_agent', { p_user_id: userId })
  return rows?.[0] ?? null
}

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
