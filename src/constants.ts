import type { Buffer } from 'node:buffer'

/**
 * @description Major version
 */
export const TAC_PLUS_MAJOR_VER = 0x0C

/**
 * @description Minor version
 */
export const TAC_PLUS_MINOR_VER_DEFAULT = 0x0
export const TAC_PLUS_MINOR_VER_ONE = 0x01

/**
 * @description Packet types
 */
export const TAC_PLUS_AUTHEN = 0x01 // Authentication
export const TAC_PLUS_AUTHOR = 0x02 // Authorization
export const TAC_PLUS_ACCT = 0x03 // Accounting

/**
 * @description Flags
 */
export const TAC_PLUS_UNENCRYPTED_FLAG = 0x01
export const TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04

/**
 * @description Authentication actions
 */
export const TAC_PLUS_AUTHEN_LOGIN = 0x01
export const TAC_PLUS_AUTHEN_CHPASS = 0x02
export const TAC_PLUS_AUTHEN_SENDAUTH = 0x04

/**
 * @description Priv level
 */
export const TAC_PLUS_PRIV_LVL_MAX = 0x0F
export const TAC_PLUS_PRIV_LVL_ROOT = 0x0F
export const TAC_PLUS_PRIV_LVL_USER = 0x01
export const TAC_PLUS_PRIV_LVL_MIN = 0x00

/**
 * @description Authentication types
 */
export const TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
export const TAC_PLUS_AUTHEN_TYPE_PAP = 0x02
export const TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03
export const TAC_PLUS_AUTHEN_TYPE_ARAP = 0x04
export const TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05
export const TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06

/**
 * @description Authentication Services
 */
export const TAC_PLUS_AUTHEN_SVC_NONE = 0x00
export const TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01
export const TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02
export const TAC_PLUS_AUTHEN_SVC_PPP = 0x03
export const TAC_PLUS_AUTHEN_SVC_ARAP = 0x04
export const TAC_PLUS_AUTHEN_SVC_PT = 0x05
export const TAC_PLUS_AUTHEN_SVC_RCMD = 0x06
export const TAC_PLUS_AUTHEN_SVC_X25 = 0x07
export const TAC_PLUS_AUTHEN_SVC_NASI = 0x08
export const TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09

/**
 * @description Authentication Response Status
 */
export const TAC_PLUS_AUTHEN_STATUS_PASS = 0x01
export const TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02
export const TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
export const TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
export const TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
export const TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
export const TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07
export const TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21

/**
 * @description Authentication Response Flags
 */
export const TAC_PLUS_REPLY_FLAG_NOECHO = 0x01

/**
 * @description Authentication continue flags
 */
export const TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01

/**
 * @description Authorization - auth method
 */
export const TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00
export const TAC_PLUS_AUTHEN_METH_NONE = 0x01
export const TAC_PLUS_AUTHEN_METH_KRB5 = 0x02
export const TAC_PLUS_AUTHEN_METH_LINE = 0x03
export const TAC_PLUS_AUTHEN_METH_ENABLE = 0x04
export const TAC_PLUS_AUTHEN_METH_LOCAL = 0x05
export const TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06
export const TAC_PLUS_AUTHEN_METH_GUEST = 0x08
export const TAC_PLUS_AUTHEN_METH_RADIUS = 0x10
export const TAC_PLUS_AUTHEN_METH_KRB4 = 0x11
export const TAC_PLUS_AUTHEN_METH_RCMD = 0x20

/**
 * @description Authorization - auth status
 */
export const TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01
export const TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
export const TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10
export const TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11
export const TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21

/**
 * @description Accounting - flags
 */
export const TAC_PLUS_ACCT_FLAG_START = 0x02
export const TAC_PLUS_ACCT_FLAG_STOP = 0x04
export const TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08

/**
 * @description Accounting - status
 */
export const TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
export const TAC_PLUS_ACCT_STATUS_ERROR = 0x02
export const TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21

export const HEADER_LENGTH = 12

export const DEFAULT_OPTIONS = {
  majorVersion: 0x0,
  minorVersion: 0x0,
  type: 0x0,
  sequenceNumber: 0x1,
  flags: exports.TAC_PLUS_UNENCRYPTED_FLAG,
  sessionId: 0x0,
  length: 0x0,
}

export interface AuthOptions {
  action: number
  privLvl: number
  authenType: number
  authenService: number
  user: string
  port: string
  remAddr: string
  data: null | Buffer
}

export const DEFAULT_AUTH_OPTIONS: AuthOptions = {
  action: 0,
  privLvl: 0,
  authenType: 0,
  authenService: 0,
  user: '',
  port: '',
  remAddr: '',
  data: null,
}

export interface ReplyOptions {
  status: number
  flags: number
  message: null | string
  data: null | Buffer
}

export const DEFAULT_REPLY_OPTIONS: ReplyOptions = {
  status: TAC_PLUS_AUTHEN_STATUS_ERROR,
  flags: 0x00,
  message: null,
  data: null,
}
