import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in React component tree:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const errorMessage =
        this.state.error instanceof Error
          ? this.state.error.message
          : typeof this.state.error === 'string'
          ? this.state.error
          : 'An unexpected application error occurred.';

      return (
        <div className="min-h-screen flex items-center justify-center p-6 bg-[#faf8f5]">
          <div className="bg-white p-8 rounded-[16px] shadow-subtle w-full max-w-md border border-warm-mist text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-red-50 text-red-600 flex items-center justify-center mx-auto">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-[18px] font-semibold text-ink">Something went wrong</h2>
            <p className="text-[14px] text-graphite">
              {errorMessage}
            </p>
            <div className="pt-2 flex gap-3 justify-center">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 bg-deep-teal text-white rounded-btn text-[14px] font-medium hover:bg-ink transition-colors"
              >
                Reload Page
              </button>
              <button
                onClick={() => {
                  window.localStorage.removeItem('cybog_token');
                  window.localStorage.removeItem('cybog_user');
                  window.location.href = '/';
                }}
                className="px-4 py-2 bg-warm-mist/30 text-ink rounded-btn text-[14px] font-medium hover:bg-warm-mist/60 transition-colors"
              >
                Return to Login
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
