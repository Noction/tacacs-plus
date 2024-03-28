import { Buffer } from 'node:buffer'
import { AUTHEN_TYPES, isAuthenService, isPrivLevel } from './common'

export const AUTHEN_METHODS = {
  TAC_PLUS_AUTHEN_METH_NOT_SET: 0x00,
  TAC_PLUS_AUTHEN_METH_NONE: 0x01,
  TAC_PLUS_AUTHEN_METH_KRB5: 0x02,
  TAC_PLUS_AUTHEN_METH_LINE: 0x03,
  TAC_PLUS_AUTHEN_METH_ENABLE: 0x04,
  TAC_PLUS_AUTHEN_METH_LOCAL: 0x05,
  TAC_PLUS_AUTHEN_METH_TACACSPLUS: 0x06,
  TAC_PLUS_AUTHEN_METH_GUEST: 0x08,
  TAC_PLUS_AUTHEN_METH_RADIUS: 0x10,
  TAC_PLUS_AUTHEN_METH_KRB4: 0x11,
  TAC_PLUS_AUTHEN_METH_RCMD: 0x20,
} as const

const ALLOWED_AUTHEN_METHODS = Object.values(AUTHEN_METHODS)

type AuthenMethod = typeof ALLOWED_AUTHEN_METHODS[number]

function isAuthenMethod(maybeAuthenMethod: number): maybeAuthenMethod is AuthenMethod {
  return (ALLOWED_AUTHEN_METHODS as number[]).includes(maybeAuthenMethod)
}

export const AUTHORIZATION_AUTHEN_TYPES = {
  ...AUTHEN_TYPES,
  TAC_PLUS_AUTHEN_TYPE_NOT_SET: 0x00,
} as const

export const ALLOWED_AUTHORIZATION_AUTHEN_TYPES = Object.values(AUTHORIZATION_AUTHEN_TYPES)

export type AuthorizationAuthenType = typeof ALLOWED_AUTHORIZATION_AUTHEN_TYPES[number]

interface UnknownAuthorizationRequest {
  authenMethod: number
  privLvl: number
  authenType: number
  authenService: number
}

function _validateAuthorizationRequest({ authenMethod, privLvl, authenType, authenService }: UnknownAuthorizationRequest) {
  if (!isAuthenMethod(authenMethod)) {
    throw new Error('Invalid authen method')
  }

  if (!isPrivLevel(privLvl)) {
    throw new Error('Invalid privilege level')
  }

  if (!isAuthorizationAuthenType(authenType)) {
    throw new Error('Invalid authen type')
  }

  if (!isAuthenService(authenService)) {
    throw new Error('Invalid authen service')
  }

  return {
    authenMethod,
    privLvl,
    authenType,
    authenService,
  }
}

export function isAuthorizationAuthenType(maybeAuthenType: number): maybeAuthenType is AuthorizationAuthenType {
  return (ALLOWED_AUTHORIZATION_AUTHEN_TYPES as number[]).includes(maybeAuthenType)
}

export const AUTHORIZATION_STATUS = {
  TAC_PLUS_AUTHOR_STATUS_PASS_ADD: 0x01,
  TAC_PLUS_AUTHOR_STATUS_PASS_REPL: 0x02,
  TAC_PLUS_AUTHOR_STATUS_FAIL: 0x10,
  TAC_PLUS_AUTHOR_STATUS_ERROR: 0x11,
  TAC_PLUS_AUTHOR_STATUS_FOLLOW: 0x21,
} as const

export const ALLOWED_AUTHORIZATION_STATUS = Object.values(AUTHORIZATION_STATUS)

type AuthorizationStatus = typeof ALLOWED_AUTHORIZATION_STATUS[number]

function isAuthorizationStatus(maybeStatus: number): maybeStatus is AuthorizationStatus {
  return (ALLOWED_AUTHORIZATION_STATUS as number[]).includes(maybeStatus)
}

interface UnknownAuthorizationReply {
  status: number
}

function _validateAuthReply({ status }: UnknownAuthorizationReply) {
  if (!isAuthorizationStatus(status)) {
    throw new Error('Invalid status')
  }

  return { status }
}

export class Authorization {
  static createAuthRequest(args: CreateAuthorizationRequestArgs) {
    const username = args.username
    const authenMethod = args.authenMethod
    const privLvl = args.privLvl
    const authenType = args.authenType
    const service = args.service
    const argss = args.arguments ?? []
    const remAddr = args.remAddr ?? ''
    const port = args.port ?? ''

    const usernameBuffer = Buffer.from(username)
    const remAddrBuffer = Buffer.from(remAddr)
    const portBuffer = Buffer.from(port)

    const headerLength = 8
    const argLenSum = argss.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0)
    const totalLength = headerLength + usernameBuffer.length + remAddrBuffer.length + portBuffer.length + argLenSum

    const header = Buffer.alloc(totalLength)
    header.writeUInt8(authenMethod, 0)
    header.writeUInt8(privLvl, 1)
    header.writeUInt8(authenType, 2)
    header.writeUInt8(service, 3)
    header.writeUInt8(usernameBuffer.length, 4)
    header.writeUInt8(portBuffer.length, 5)
    header.writeUInt8(remAddrBuffer.length, 6)
    header.writeUInt8(argss.length, 7)

    let offset = headerLength
    for (const arg of argss) {
      const argBuffer = Buffer.from(arg)
      header.writeUInt8(argBuffer.length, offset)
      offset++
    }

    offset = headerLength
    header.write(username, offset)
    offset += usernameBuffer.length
    header.write(port, offset)
    offset += portBuffer.length
    header.write(remAddr, offset)
    offset += remAddrBuffer.length

    for (const arg of argss) {
      const argBuffer = Buffer.from(arg)
      header.write(argBuffer.toString(), offset)
      offset += argBuffer.length
    }

    return header
  }

  static readonly REQUEST_MIN_LENGTH = 8
  static readonly REPLY_MIN_LENGTH = 6
}
