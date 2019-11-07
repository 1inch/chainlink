/**
 * NOTIFY_ERROR
 */

export type NotifyErrorAction = { type: 'NOTIFY_ERROR'; text: string }

/**
 * ADMIN_SIGNIN_SUCCEEDED
 */

export type FetchAdminSigninSucceededAction = {
  type: 'FETCH_ADMIN_SIGNIN_SUCCEEDED'
  data: {
    allowed: boolean
  }
}

/**
 * FETCH_ADMIN_SIGNIN_ERROR
 */

export type FetchAdminSigninErrorAction = {
  type: 'FETCH_ADMIN_SIGNIN_ERROR'
  error: Error
}

/**
 * FETCH_ADMIN_SIGNOUT_SUCCEEDED
 */

export type FetchAdminSignoutSucceededAction = {
  type: 'FETCH_ADMIN_SIGNOUT_SUCCEEDED'
}

/**
 * FETCH_ADMIN_OPERATORS_SUCCEEDED
 */

export interface AdminOperatorsNormalizedMeta {
  currentPageOperators: {
    data: any[]
    meta: {
      count: number
    }
  }
}

export interface AdminOperatorsNormalizedData {
  chainlinkNodes: any
  meta: AdminOperatorsNormalizedMeta
}

export type FetchAdminOperatorsSucceededAction = {
  type: 'FETCH_ADMIN_OPERATORS_SUCCEEDED'
  data: AdminOperatorsNormalizedData
}

/**
 * FETCH_JOB_RUNS_SUCCEEDED
 */

export interface JobRunsNormalizedMeta {
  currentPageJobRuns: {
    data: any[]
    meta: {
      count: number
    }
  }
}

export interface JobRunsNormalizedData {
  chainlinkNodes: any[]
  jobRuns: any
  meta: JobRunsNormalizedMeta
}

export type FetchJobRunsSucceededAction = {
  type: 'FETCH_JOB_RUNS_SUCCEEDED'
  data: JobRunsNormalizedData
}

/**
 * FETCH_JOB_RUN_SUCCEEDED
 */
export interface JobRunNormalizedMeta {
  jobRun: any
}

export interface JobRunNormalizedData {
  chainlinkNodes: any[]
  taskRuns: any[]
  jobRuns: any
  meta: JobRunNormalizedMeta
}

export type FetchJobRunSucceededAction = {
  type: 'FETCH_JOB_RUN_SUCCEEDED'
  data: JobRunNormalizedData
}

export type UpdateQueryAction = { type: 'QUERY_UPDATED'; data?: string }

export type Actions =
  | NotifyErrorAction
  | FetchAdminSigninSucceededAction
  | FetchAdminSigninErrorAction
  | FetchAdminSignoutSucceededAction
  | FetchAdminOperatorsSucceededAction
  | FetchJobRunsSucceededAction
  | FetchJobRunSucceededAction
  | UpdateQueryAction