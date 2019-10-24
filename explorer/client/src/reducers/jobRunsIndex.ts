import { Actions } from './actions'

export interface State {
  items?: string[]
  count?: number
}

const INITIAL_STATE: State = {}

export default (state: State = INITIAL_STATE, action: Actions): State => {
  switch (action.type) {
    case 'FETCH_JOB_RUNS_SUCCEEDED':
      return {
        items: action.data.meta.currentPageJobRuns.data.map(r => r.id),
        count: action.data.meta.currentPageJobRuns.meta.count,
      }
    case 'FETCH_JOB_RUN_SUCCEEDED':
      return INITIAL_STATE
    default:
      return state
  }
}
