// Rook monogram — a chess rook (castle), fortress-implying, in the accent.
export function RookMark({ className = "h-8 w-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" aria-hidden="true">
      <path
        d="M9 8 V11 L11 11 V9.5 H13.2 V11 H15 V9.5 H17 V11 H18.8 V9.5 H21 V11 H23 V8 H9 Z M10 11 L10.8 20 H21.2 L22 11 Z M9 20 H23 L24 25 H8 Z"
        fill="var(--accent)"
      />
      <path d="M8 25 H24 V27 H8 Z" fill="var(--fg-muted)" />
    </svg>
  );
}
