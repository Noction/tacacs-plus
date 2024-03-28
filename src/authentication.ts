import { Buffer } from 'node:buffer'
import type { HeaderRecord } from './header'
import type { AuthenService, AuthenType, PrivLevel } from './common'
import { AUTHEN_SERVICE, isAuthenService, isAuthenType, isPrivLevel } from './common'

export const AUTH_START_ACTIONS = {
  TAC_PLUS_AUTHEN_LOGIN: 0x01,
  TAC_PLUS_AUTHEN_CHPASS: 0x02,
  TAC_PLUS_AUTHEN_SENDAUTH: 0x04,
} as const

const ALLOWED_AUTH_START_ACTIONS_VALUES = Object.values(AUTH_START_ACTIONS)

type AuthStartAction = typeof ALLOWED_AUTH_START_ACTIONS_VALUES[number]

function isAuthStartAction(maybeAction: number): maybeAction is AuthStartAction {
  return (ALLOWED_AUTH_START_ACTIONS_VALUES as number[]).includes(maybeAction)
}

export const PrivilegeLevels = {
  TAC_PLUS_PRIV_LVL_MIN: 0x00,
  TAC_PLUS_PRIV_LVL_USER: 0x01,
  TAC_PLUS_PRIV_LVL_ROOT: 0x0F,
  TAC_PLUS_PRIV_LVL_MAX: 0x0F,
} as const

interface AuthStartRecord {
  action: AuthStartAction
  privLvl: PrivLevel
  authenType: AuthenType
  authenService: AuthenService
  userLen: number
  user: string | null
  portLen: number
  port: string | null
  remAddrLen: number
  remAddr: string | null
  dataLen: number
  content: Buffer | null
}

type UnknownAuthStart = Record<'action' | 'privLvl' | 'authenType' | 'authenService' | 'userLen' | 'portLen' | 'remAddrLen' | 'dataLen', number>

function validateAuthStart({ action, privLvl, authenType, authenService, userLen, portLen, remAddrLen, dataLen }: UnknownAuthStart) {
  if (!isAuthStartAction(action)) {
    throw new Error('Invalid action')
  }

  if (!isPrivLevel(privLvl)) {
    throw new Error('Invalid privilege level')
  }

  if (!isAuthenType(authenType)) {
    throw new Error('Invalid authentication type')
  }

  if (!isAuthenService(authenService)) {
    throw new Error('Invalid authentication service')
  }

  return {
    action,
    privLvl,
    authenType,
    authenService,
    userLen,
    portLen,
    remAddrLen,
    dataLen,
  }
}

export const STATUSES = {
  TAC_PLUS_AUTHEN_STATUS_PASS: 0x01,
  TAC_PLUS_AUTHEN_STATUS_FAIL: 0x02,
  TAC_PLUS_AUTHEN_STATUS_GETDATA: 0x03,
  TAC_PLUS_AUTHEN_STATUS_GETUSER: 0x04,
  TAC_PLUS_AUTHEN_STATUS_GETPASS: 0x05,
  TAC_PLUS_AUTHEN_STATUS_RESTART: 0x06,
  TAC_PLUS_AUTHEN_STATUS_ERROR: 0x07,
  TAC_PLUS_AUTHEN_STATUS_FOLLOW: 0x21,
} as const

const ALLOWED_STATUSES = Object.values(STATUSES)

type Status = typeof ALLOWED_STATUSES[number]

function isStatus(maybeStatus: number): maybeStatus is Status {
  return (ALLOWED_STATUSES as number[]).includes(maybeStatus)
}

export const AUTH_REPLY_FLAGS = {
  TAC_PLUS_REPLY_NO_ACTION: 0x00,
  TAC_PLUS_REPLY_FLAG_NOECHO: 0x01,
} as const

const ALLOWED_AUTH_REPLY_FLAGS = Object.values(AUTH_REPLY_FLAGS)

type ReplyFlag = typeof ALLOWED_AUTH_REPLY_FLAGS[number]

function isReplyFlag(maybeReplyFlag: number): maybeReplyFlag is ReplyFlag {
  return (ALLOWED_AUTH_REPLY_FLAGS as number[]).includes(maybeReplyFlag)
}

interface AuthReplyRecord {
  status: Status
  flags: ReplyFlag
  messageLength: number
  contentLength: number
  content: string | null
  message: string | null
}

type UnknownAuthReply = Record<'status' | 'flags' | 'messageLength' | 'contentLength', number>

function validateAuthReply({ status, flags, messageLength, contentLength }: UnknownAuthReply) {
  if (!isStatus(status)) {
    throw new Error('Invalid status')
  }

  if (!isReplyFlag(flags)) {
    throw new Error('Invalid reply flag')
  }

  return {
    status,
    flags,
    messageLength,
    contentLength,
  }
}

export const AUTH_CONTINUE_FLAGS = {
  TAC_PLUS_CONTINUE_FLAG_ABORT: 0x01,
} as const

const ALLOWED_AUTH_CONTINUE_FLAGS = Object.values(AUTH_CONTINUE_FLAGS)

type ContinueFlag = typeof ALLOWED_AUTH_CONTINUE_FLAGS[number]

function isContinueFlag(maybeContinueFlag: number): maybeContinueFlag is ContinueFlag {
  return (ALLOWED_AUTH_CONTINUE_FLAGS as number[]).includes(maybeContinueFlag)
}

interface AuthContinueRecord {
  userMessageLength: number
  dataLength: number
  flags: ContinueFlag
  userMessage: string | null
  content: string | null
}

type UnknownAuthContinue = Record<'userMessageLength' | 'dataLength' | 'flags', number>

function validateAuthContinue({ userMessageLength, dataLength, flags }: UnknownAuthContinue) {
  if (!isContinueFlag(flags)) {
    throw new Error('Invalid continue flag')
  }

  return {
    userMessageLength,
    dataLength,
    flags,
  }
}

interface CreateAuthStartArgs {
  action: AuthStartAction
  privLvl?: PrivLevel
  authenType: AuthenType
  authenService: AuthenService
  username: string
  port?: string
  remAddr?: string
  data?: Buffer
}

const TAC_PLUS_VIRTUAL_PORT = ''
const TAC_PLUS_VIRTUAL_REM_ADDR = ''

interface CreateAuthContinueArgs {
  password: string
  flags: number
  data?: Buffer
}

export class Authentication {
  static decodeAuthStart(data: Buffer, length: HeaderRecord['length']): AuthStartRecord {
    if (data.length < Authentication.START_MIN_LENGTH) {
      throw new Error('Invalid auth start length')
    }

    const authStart = validateAuthStart({
      action: data.readUInt8(0),
      privLvl: data.readUInt8(1),
      authenType: data.readUInt8(2),
      authenService: data.readUInt8(3),
      userLen: data.readUInt8(4),
      portLen: data.readUInt8(5),
      remAddrLen: data.readUInt8(6),
      dataLen: data.readUInt8(7),
    })

    let currentPosition = 8
    let user = null
    let port = null
    let remAddr = null
    let content = null

    if (authStart.userLen > 0) {
      user = data.subarray(currentPosition, currentPosition + authStart.userLen).toString('utf8')
      currentPosition += authStart.userLen
    }

    if (authStart.portLen > 0) {
      port = data.subarray(currentPosition, currentPosition + authStart.portLen).toString('ascii')
      currentPosition += authStart.portLen
    }

    if (authStart.remAddrLen > 0) {
      remAddr = data.subarray(currentPosition, currentPosition + authStart.remAddrLen).toString('ascii')
      currentPosition += authStart.remAddrLen
    }

    if (authStart.dataLen > 0) {
      content = data.subarray(currentPosition, currentPosition + authStart.dataLen)
      currentPosition += authStart.dataLen
    }

    if (currentPosition !== length) {
      throw new Error('Incorrect length in header')
    }

    return {
      ...authStart,
      user,
      port,
      remAddr,
      content,
    }
  }

  static decodeAuthReply(data: Buffer, length: HeaderRecord['length']): AuthReplyRecord {
    if (data.length < Authentication.REPLY_MIN_LENGTH) {
      throw new Error('Invalid reply header length')
    }

    const authReply = validateAuthReply({
      status: (data.readUInt8(0) & 0xF),
      flags: (data.readUInt8(1) & 0xF),
      messageLength: data.readUInt16BE(2),
      contentLength: data.readUInt16BE(4),
    })

    let message = null
    let content = null
    let pos = 6

    if (authReply.messageLength > 0) {
      message = data.subarray(pos, pos + authReply.messageLength).toString('ascii')
      pos += authReply.messageLength
    }

    if (authReply.contentLength > 0) {
      content = data.subarray(pos, pos + authReply.contentLength).toString('utf8')
      pos += authReply.contentLength
    }

    if (pos !== length) {
      throw new Error('Incorrect length in header')
    }

    return {
      ...authReply,
      message,
      content,
    }
  }

  static decodeAuthContinue(data: Buffer, length: HeaderRecord['length']): AuthContinueRecord {
    if (data.length < Authentication.CONTINUE_MIN_LENGTH) {
      throw new Error('Invalid continue header length')
    }

    const authContinue = validateAuthContinue({
      userMessageLength: data.readUInt16BE(0),
      dataLength: data.readUInt16BE(2),
      flags: data.readUInt8(4),
    })

    const userMessage = authContinue.userMessageLength > 0
      ? data.subarray(5, 5 + authContinue.userMessageLength).toString('ascii')
      : null

    const content = authContinue.dataLength > 0
      ? data.subarray(5 + authContinue.userMessageLength, 5 + authContinue.userMessageLength + authContinue.dataLength).toString('utf8')
      : null

    const pos = 5 + authContinue.userMessageLength + authContinue.dataLength

    if (pos !== length) {
      throw new Error('Incorrect length in header')
    }

    return {
      ...authContinue,
      userMessage,
      content,
    }
  }

  static createAuthStart(options: CreateAuthStartArgs) {
    const username = options.username
    const action = AUTH_START_ACTIONS.TAC_PLUS_AUTHEN_LOGIN
    const privLvl = options.privLvl ?? PrivilegeLevels.TAC_PLUS_PRIV_LVL_MIN
    const authenType = options.authenType
    const service = AUTHEN_SERVICE.TAC_PLUS_AUTHEN_SVC_LOGIN
    const data = options.data ?? Buffer.alloc(0)
    const remAddr = options.remAddr ?? TAC_PLUS_VIRTUAL_REM_ADDR
    const port = options.port ?? TAC_PLUS_VIRTUAL_PORT

    const usernameBuffer = Buffer.from(username)
    const remAddrBuffer = Buffer.from(remAddr)
    const portBuffer = Buffer.from(port)

    const header = Buffer.alloc(8)
    header.writeUInt8(action, 0)
    header.writeUInt8(privLvl, 1)
    header.writeUInt8(authenType, 2)
    header.writeUInt8(service, 3)
    header.writeUInt8(usernameBuffer.length, 4)
    header.writeUInt8(portBuffer.length, 5)
    header.writeUInt8(remAddrBuffer.length, 6)
    header.writeUInt8(data.length, 7)

    return Buffer.concat([header, usernameBuffer, portBuffer, remAddrBuffer, data])
  }

  static createAuthContinue(options: any) {
    options.flags = options.flags ?? 0x00
    options.userMessage = options.userMessage || null
    options.data = options.data || null

    const bSize = 2 + 2 + 1 + (options.userMessage ? options.userMessage.length : 0) + (options.data ? options.data.length : 0)
    let resp = Buffer.alloc(bSize)
    let offset = 0

    resp.writeInt16BE(options.userMessage ? options.userMessage.length : 0, offset)
    offset += 2
    resp.writeInt16BE(options.data ? options.data.length : 0, offset)
    offset += 2

    resp.writeUInt8(options.flags, offset)
    offset += 1

    if (options.userMessage) {
      resp.write(options.userMessage, offset)
      offset += options.userMessage.length
    }

    if (options.data) {
      if (options.data instanceof Buffer) {
        resp = Buffer.concat([resp, options.data])
      }

      else { resp.write(options.data, offset) }

      offset += options.data.length
    }

    return resp
  }

  static createAuthContinue2(args: CreateAuthContinueArgs) {
    const password = args.password
    const data = args.data ?? Buffer.alloc(0)
    const flags = args.flags ?? 0 // TODO(lwvemike): see why this is needed 0

    const passwordBuffer = Buffer.from(password)
    const header = Buffer.alloc(5)
    header.writeUInt16BE(passwordBuffer.length, 0)
    header.writeUInt16BE(data.length, 2)
    header.writeUInt8(flags, 4)

    return Buffer.concat([header, passwordBuffer, data])
  }

  static readonly START_MIN_LENGTH = 8
  static readonly REPLY_MIN_LENGTH = 6
  static readonly CONTINUE_MIN_LENGTH = 5
}
