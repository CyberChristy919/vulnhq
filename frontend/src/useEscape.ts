import { useEffect } from 'react'

// Calls onEscape when the Escape key is pressed, while the panel is on screen
export function useEscape(onEscape: () => void) {
  useEffect(() => {
    function handleKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onEscape()
    }
    // Start listening for key presses anywhere on the page
    window.addEventListener('keydown', handleKey)
    // Clean up: stop listening when the panel closes
    return () => window.removeEventListener('keydown', handleKey)
  }, [onEscape])
}