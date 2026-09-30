import { createClient } from '@supabase/supabase-js'

// Browser client: public anon key from env (benchmark fixture).
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
)
