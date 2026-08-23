'use client';

/**
 * Last-resort boundary: catches failures in the root layout itself, so it has
 * to render its own <html> and <body> and cannot rely on providers, fonts or
 * the app stylesheet being available. Styles are inline for that reason.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#09090b',
          color: '#fafafa',
          fontFamily: 'ui-sans-serif, system-ui, sans-serif',
          padding: '1.5rem',
        }}
      >
        <div style={{ maxWidth: '32rem', textAlign: 'center' }}>
          <p
            style={{
              fontFamily: 'ui-monospace, monospace',
              fontSize: '0.75rem',
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: '#a1a1aa',
            }}
          >
            Application error
          </p>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 600, margin: '0.5rem 0 0.75rem' }}>
            Quarantine failed to start
          </h1>
          <p style={{ color: '#a1a1aa', fontSize: '0.875rem', lineHeight: 1.6 }}>
            The application could not render. The failure has been recorded.
          </p>
          {error.digest ? (
            <p
              style={{
                color: '#71717a',
                fontFamily: 'ui-monospace, monospace',
                fontSize: '0.75rem',
                marginTop: '0.75rem',
              }}
            >
              Reference: {error.digest}
            </p>
          ) : null}
          <button
            type="button"
            onClick={reset}
            style={{
              marginTop: '1.5rem',
              background: '#3b82f6',
              color: '#08111f',
              border: 0,
              borderRadius: '0.375rem',
              padding: '0.5rem 1rem',
              fontSize: '0.875rem',
              fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  );
}
