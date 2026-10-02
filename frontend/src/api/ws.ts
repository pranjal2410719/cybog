/**
 * WebSocket connection manager for real-time assessment updates.
 *
 * Connects to the backend's `/ws/assessments/{assessment_id}` route (mounted
 * at the app root, NOT under `/api/v1`). URL is built through `wsUrl()` so
 * the base never appears in component code.
 */

import { wsUrl } from './config';

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private assessmentId: string;
  private onProgress: ((data: any) => void) | null = null;
  private onFindingUpdateCallback: ((data: any) => void) | null = null;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelay: number = 1000;

  constructor(assessmentId: string) {
    this.assessmentId = assessmentId;
  }

  connect(): void {
    this.ws = new WebSocket(wsUrl(`/assessments/${this.assessmentId}`));

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
    };

    this.ws.onmessage = (event) => {
      try {
        this.handleMessage(JSON.parse(event.data));
      } catch {
        // Ignore malformed messages; keep the socket alive.
      }
    };

    this.ws.onclose = () => {
      this.attemptReconnect();
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror; reconnect logic lives there.
    };
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  onProgressUpdate(callback: (data: any) => void): void {
    this.onProgress = callback;
  }

  onFindingUpdate(callback: (data: any) => void): void {
    this.onFindingUpdateCallback = callback;
  }

  private handleMessage(data: any): void {
    switch (data.type) {
      case 'progress_update':
        this.onProgress?.(data);
        break;
      case 'finding_update':
        this.onFindingUpdateCallback?.(data);
        break;
      case 'connected':
      case 'echo':
        break;
      default:
        break;
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      return;
    }
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }
}