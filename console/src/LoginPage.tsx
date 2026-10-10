import { useState, type FormEvent } from "react";

interface Props {
  onAuthenticated: () => void;
  loading: boolean;
}

export default function LoginPage({ onAuthenticated, loading }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!username.trim() || !password || pending) return;
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/portal/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const result = await response.json() as { error?: string };
      if (!response.ok) throw new Error(result.error ?? "Sign-in failed");
      setPassword("");
      onAuthenticated();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in service unavailable");
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="mon-login-page" data-testid="unauthenticated">
      <section className="mon-login-left">
        <div className="mon-login-brand"><span className="mon-brand-mark">M</span><span>MON <small>/ SECURITY FABRIC</small></span></div>
        <div className="mon-login-statement">
          <span className="mon-eyebrow mon-light">SECURITY OPERATIONS PLATFORM / LAB ENVIRONMENT</span>
          <h1>Welcome to<br/><strong>MON.</strong></h1>
          <p className="mon-full-form">Monitoring Operations Network</p>
          <div className="mon-login-rule" />
          <p>Observe the signal. Reconstruct the route. Investigate the evidence. Respond with control.</p>
        </div>
        <div className="mon-login-left-footer">
          <span>01 / DETECT</span><span>02 / INVESTIGATE</span>
          <span>03 / CONTAIN</span><span>04 / RECOVER</span>
        </div>
      </section>
      <section className="mon-login-right">
        <div className="mon-login-topline"><span>SECURE OPERATOR ACCESS</span><span data-testid="operator-context">not authenticated</span></div>
        <div className="mon-login-form-wrap">
          <span className="mon-eyebrow">AUTHENTICATION GATEWAY</span>
          <h2>Operator sign in</h2>
          <p>Access live telemetry, incident evidence, enforcement controls and audit history.</p>
          <form onSubmit={event => void submit(event)} className="mon-login-form">
            <label htmlFor="mon-user">OPERATOR ID</label>
            <input id="mon-user" autoComplete="username" value={username}
              onChange={event => setUsername(event.target.value)}
              placeholder="Enter operator ID" maxLength={80} required />
            <label htmlFor="mon-password">PASSWORD</label>
            <input id="mon-password" type="password" autoComplete="current-password"
              value={password} onChange={event => setPassword(event.target.value)}
              placeholder="Enter password" required />
            <button type="submit" disabled={pending || loading}>
              {pending ? "VERIFYING…" : "SIGN IN TO MON"} <span aria-hidden="true">↗</span>
            </button>
            {error && <p className="mon-login-error" role="alert">{error}</p>}
          </form>
          <p className="mon-login-legal">Authorized lab operators only. Authentication is verified server-side; response actions remain separately policy-gated.</p>
        </div>
        <div className="mon-login-bottomline">
          <span>MON COMMAND / OPERATOR CONSOLE</span>
          <span>BLACK / WHITE / EVIDENCE FIRST</span>
        </div>
      </section>
    </main>
  );
}
