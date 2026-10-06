// Hook to convert various error shapes into a user-friendly string message
// Returns a function `getMessage` that takes any error and returns a string.
import { useCallback } from "react";

export const useApiError = () => {
  const getMessage = useCallback((err: unknown): string => {
    if (!err) return "An unknown error occurred";
    // Axios-like error with response data
    const maybeResponse = (err as any).response;
    if (maybeResponse && maybeResponse.data) {
      // Prefer a 'detail' field if present, otherwise fallback to the data itself
      const detail = (maybeResponse.data as any).detail;
      if (detail) return String(detail);
      return typeof maybeResponse.data === "string"
        ? maybeResponse.data
        : JSON.stringify(maybeResponse.data);
    }
    // Fallback to standard error message if available
    const message = (err as any).message;
    if (message) return String(message);
    // As a last resort stringify the error
    return String(err);
  }, []);

  return { getMessage };
};
