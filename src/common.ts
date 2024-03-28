export type PrivLevel = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15

export function isPrivLevel(maybePrivLevel: number): maybePrivLevel is PrivLevel {
  return maybePrivLevel > -1 && maybePrivLevel < 16
}

export const AUTHEN_TYPES = {
  TAC_PLUS_AUTHEN_TYPE_ASCII: 0x01,
  TAC_PLUS_AUTHEN_TYPE_PAP: 0x02,
  TAC_PLUS_AUTHEN_TYPE_CHAP: 0x03,
  TAC_PLUS_AUTHEN_TYPE_MSCHAP: 0x05,
  TAC_PLUS_AUTHEN_TYPE_MSCHAPV2: 0x06,
} as const

export const ALLOWED_AUTHEN_TYPES = Object.values(AUTHEN_TYPES)

export type AuthenType = typeof ALLOWED_AUTHEN_TYPES[number]

export function isAuthenType(maybeAuthenType: number): maybeAuthenType is AuthenType {
  return (ALLOWED_AUTHEN_TYPES as number[]).includes(maybeAuthenType)
}

export const AUTHEN_SERVICE = {
  TAC_PLUS_AUTHEN_SVC_NONE: 0x00,
  TAC_PLUS_AUTHEN_SVC_LOGIN: 0x01,
  TAC_PLUS_AUTHEN_SVC_ENABLE: 0x02,
  TAC_PLUS_AUTHEN_SVC_PPP: 0x03,
  TAC_PLUS_AUTHEN_SVC_PT: 0x05,
  TAC_PLUS_AUTHEN_SVC_RCMD: 0x06,
  TAC_PLUS_AUTHEN_SVC_X25: 0x07,
  TAC_PLUS_AUTHEN_SVC_NASI: 0x08,
  TAC_PLUS_AUTHEN_SVC_FWPROXY: 0x09,
} as const

export const ALLOWED_AUTHEN_SERVICE = Object.values(AUTHEN_SERVICE)

export type AuthenService = typeof ALLOWED_AUTHEN_SERVICE[number]

export function isAuthenService(maybeAuthenService: number): maybeAuthenService is AuthenService {
  return (ALLOWED_AUTHEN_SERVICE as number[]).includes(maybeAuthenService)
}
