import type { AmbushApi } from '@shared/ipc'

declare global {
  interface Window {
    ambush: AmbushApi
  }
}

export {}
