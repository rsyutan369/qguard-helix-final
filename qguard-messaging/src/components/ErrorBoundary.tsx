import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

// Last-line safety net: a render error in any page/gate below this boundary
// shows a recoverable message instead of blanking the entire window. `resetKey`
// lets a parent clear the error automatically on navigation (a new key remounts
// the fallback back into the children).
interface Props {
  children: ReactNode;
  resetKey?: unknown;
  label?: string;
}
interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface it for debugging; never swallow silently.
    console.error("[QGuard] UI crash caught by ErrorBoundary:", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    // Auto-clear when the parent signals a context change (e.g. page switch).
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="w-full max-w-md rounded-xl border border-rose-200 bg-white p-6 text-center shadow-soft">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-rose-50 text-rose-600">
            <AlertTriangle size={22} />
          </span>
          <h2 className="mt-3 text-lg font-bold text-ink-950">{this.props.label ?? "Something went wrong"}</h2>
          <p className="mt-1 text-sm text-ink-600">
            This screen hit an unexpected error. Your data is safe and encrypted — nothing was lost.
          </p>
          <p className="mt-2 break-words rounded-lg bg-canvas px-3 py-2 text-left font-mono text-[11px] text-ink-500">
            {this.state.error.message || String(this.state.error)}
          </p>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="mt-4 inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-cyan-700"
          >
            <RotateCcw size={16} />
            Try again
          </button>
        </div>
      </div>
    );
  }
}
