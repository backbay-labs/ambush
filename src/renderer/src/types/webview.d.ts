import type { DetailedHTMLProps, HTMLAttributes } from 'react'

// Electron's <webview> tag is not part of React's intrinsic element set.
type WebviewProps = DetailedHTMLProps<HTMLAttributes<HTMLElement>, HTMLElement> & {
  src?: string
  partition?: string
  allowpopups?: string
  preload?: string
  useragent?: string
  nodeintegration?: string
}

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      webview: WebviewProps
    }
  }
}
