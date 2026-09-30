'use client'
import { createClient } from '@supabase/supabase-js'

// FAKE benchmark key: not a real credential, signature is junk.
const SUPABASE_URL = 'http://127.0.0.1:54321'
const SERVICE_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicmVmIjoiZmFrZS1iZW5jaG1hcmstcHJvamVjdCIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.FAKEsignatureNOTrealBENCHMARKonly000000000'

// Used by the "Export subscriber stats" button.
export const adminClient = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false },
})
