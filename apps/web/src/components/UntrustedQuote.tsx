/** Untrusted document text: always escaped, always labelled, never rendered as HTML or links (CLAUDE.md §5). */
export function UntrustedQuote({ text }: { text: string }) {
  if (!text) return null;
  const shown = text.length > 400 ? text.slice(0, 400) : text;
  return (
    <figure className="border-l-[3px] border-untrusted bg-untrusted-tint p-3 rounded-panel">
      <figcaption className="mb-1 flex items-center gap-2 text-sm font-medium text-untrusted">
        <span aria-hidden="true">◇</span> From the document (not instructions)
      </figcaption>
      {/* text is a plain string in a text node: React escapes it; no dangerouslySetInnerHTML anywhere */}
      <pre className="whitespace-pre-wrap break-words font-sans text-sm text-untrusted">{shown}</pre>
    </figure>
  );
}
