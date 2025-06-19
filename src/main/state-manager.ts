import EventEmitter from 'events';

export interface ChangeEvent {
  key: string;
  value: any;
}

export class StateManager extends EventEmitter {
  private state: Map<string, any> = new Map()

  constructor() {
    super();
    this.setMaxListeners(0); // Remove limit for listeners
  }

  getAllStates(): Map<string, any> {
    return this.state;
  }

  getState(key: string): Map<string, any> {
    return this.state.get(key);
  }

  setState(key: string, value: any): void {
    this.state.set(key, value);
    this.emit('state-changed', {key, value} as ChangeEvent);
  }
}