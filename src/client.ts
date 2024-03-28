import type { Socket, TcpNetConnectOpts } from 'node:net'
import { createConnection } from 'node:net'
import { randomBytes } from 'node:crypto'
import { Buffer } from 'node:buffer'
import type { HeaderRecord, HeaderType, Secret } from './header'
import { FLAGS, HEADER_TYPES, Header, MAJOR_VERSIONS, MINOR_VERSIONS, createVersionByte } from './header'
import { Packet } from './packet'
import { AUTH_START_ACTIONS, Authentication, PrivilegeLevels, STATUSES } from './authentication'
import { AUTHEN_SERVICE, AUTHEN_TYPES } from './common'
import { notImplemented } from './utils'
import { AUTHEN_METHODS, AUTHORIZATION_AUTHEN_TYPES, Authorization } from './authorization'

interface Logger {
  log: (message: string) => void
  debug: (message: string) => void
  error: (message: string) => void
}

type Options =
  & {
    host: string
    port: number
    secret: Secret
    sessionId?: HeaderRecord['sessionId']
    logger: Logger
  }
  & Pick<HeaderRecord, 'majorVersion' | 'minorVersion'>

function randomInt(min: number, max: number) {
  if (min >= max) {
    throw new Error('min must be less than max')
  }

  const bytes = Math.ceil((Math.log2(max) + 1) / 8)

  do {
    const buffer = randomBytes(bytes)

    if (buffer[0] !== 0) {
      return buffer.readUIntBE(0, bytes) % (max - min + 1) + min
    }
  } while (true)
}

export class Client {
  readonly #host: Options['host']
  readonly #port: Options['port']
  readonly #secret: Options['secret']
  readonly #majorVersion: HeaderRecord['majorVersion']
  readonly #minorVersion: HeaderRecord['minorVersion']
  readonly #sessionId: HeaderRecord['sessionId']
  readonly #logger: Logger
  #socket?: Socket

  constructor(options: Options = Client.DEFAULT_OPTIONS) {
    this.#host = options.host
    this.#port = options.port
    this.#secret = options.secret
    this.#majorVersion = options.majorVersion
    this.#minorVersion = options.minorVersion
    this.#sessionId = options.sessionId ?? randomInt(1, 2 ** 32 - 1)
    this.#logger = options.logger
  }

  get version() {
    return createVersionByte({ majorVersion: this.#majorVersion, minorVersion: this.#minorVersion })
  }

  send(body: Buffer, type: HeaderType, seqNo: HeaderRecord['seqNo'] = 1) {
    const header = new Header({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
      type,
      flags: (this.#secret === null ? FLAGS.TAC_PLUS_UNENCRYPTED_FLAG : 0),
      seqNo,
      sessionId: this.#sessionId,
      length: body.length,
    })

    const packet = new Packet(header, body, this.#secret)

    this.#logger.debug('Created TCP socket')
    const socket = this.createSocket()

    // TODO(lwvemike): handle all socket events
    socket.write(packet.toBuffer(), (err) => {
      if (err) {
        this.#logger.error(err.message)
        // TODO(lwvemike): destroy the socket
      }
    })

    return socket
  }

  authenticate(username: string, password: string) {
    const passwordBuffer = Buffer.from(password)

    const body = Authentication.createAuthStart({
      action: AUTH_START_ACTIONS.TAC_PLUS_AUTHEN_LOGIN,
      authenType: AUTHEN_TYPES.TAC_PLUS_AUTHEN_TYPE_ASCII,
      authenService: AUTHEN_SERVICE.TAC_PLUS_AUTHEN_SVC_NONE,
      username,
      port: '',
      remAddr: '',
      data: passwordBuffer,
    })

    const header = new Header({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
      type: AUTHEN_TYPES.TAC_PLUS_AUTHEN_TYPE_ASCII,
      flags: (this.#secret === null ? FLAGS.TAC_PLUS_UNENCRYPTED_FLAG : 0),
      seqNo: 1,
      sessionId: this.#sessionId,
      length: body.length,
    })

    const packet = new Packet(header, body, this.#secret)

    const socket = this.createSocket()

    const handleSocketWriteError = (error: Error | undefined) => {
      if (error) {
        this.#logger.error(error.message)
        socket.destroy()
      }
    }

    const handleAuthReply = (data: Buffer) => {
      const authReplyResponse = Packet.decodePacket(data)

      if (authReplyResponse?.status === STATUSES.TAC_PLUS_AUTHEN_STATUS_PASS) {
        this.#logger.debug('Pass')
      }
      else if (authReplyResponse?.status === STATUSES.TAC_PLUS_AUTHEN_STATUS_FAIL) {
        this.#logger.debug('Fail')
      }
      else {
        notImplemented(`${authReplyResponse?.status} STATUS`)
      }

      this.#logger.debug('Ended')
      socket.destroy()
    }

    socket.write(packet.toBuffer(), handleSocketWriteError)

    const handleAuthContinue = (data: Buffer) => {
      socket.off('data', handleAuthContinue)
      socket.on('data', handleAuthReply)

      const _authReply = Packet.decodePacket(data)

      const authContinue = Authentication.createAuthContinue2({
        password,
        flags: 0x00,
      })

      const newHeader = new Header({
        majorVersion: this.#majorVersion,
        minorVersion: this.#minorVersion,
        type: HEADER_TYPES.TAC_PLUS_AUTHEN,
        flags: (this.#secret === null ? FLAGS.TAC_PLUS_UNENCRYPTED_FLAG : 0),
        seqNo: 3,
        sessionId: this.#sessionId,
        length: authContinue.length,
      })

      const buff = Buffer.concat([newHeader.toBuffer(), authContinue])

      socket.write(buff, handleSocketWriteError)
    }

    socket.on('data', handleAuthContinue)
  }

  authorize(username: string, _password: string) {
    const body = Authorization.createAuthRequest({
      username,
      authenMethod: AUTHEN_METHODS.TAC_PLUS_AUTHEN_METH_NOT_SET,
      privLvl: PrivilegeLevels.TAC_PLUS_PRIV_LVL_USER,
      authenType: AUTHORIZATION_AUTHEN_TYPES.TAC_PLUS_AUTHEN_TYPE_ASCII,
      service: 0,
      arguments: [],
    })

    const header = new Header({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
      type: AUTHEN_TYPES.TAC_PLUS_AUTHEN_TYPE_ASCII,
      flags: (this.#secret === null ? FLAGS.TAC_PLUS_UNENCRYPTED_FLAG : 0),
      seqNo: 1,
      sessionId: this.#sessionId,
      length: body.length,
    })

    const packet = new Packet(header, body, this.#secret)

    const socket = this.createSocket()

    const handleSocketWriteError = (error: Error | undefined) => {
      if (error) {
        this.#logger.error(error.message)
        socket.destroy()
      }
    }

    socket.write(packet.toBuffer(), handleSocketWriteError)

    socket.on('data', (data: Buffer) => {
      const _decoded = Packet.decodePacket(data)
    })
  }

  private createSocket(): Socket {
    const connection: TcpNetConnectOpts = {
      port: this.#port,
      host: this.#host,
    }

    const socket = createConnection(connection, () => {
      this.#logger.log('TACACS+ client connected')
    })

    // TODO(lwvemike): hardcoded right now, will be added in a variable in the future
    socket.setTimeout(10_000, () => {
      this.#logger.error('TACACS+ client connection timed out')
      socket.destroy()
    })

    socket.on('error', (err) => {
      this.#logger.error(err.message)
      this.#logger.debug('Destroyed socket')
      socket.destroy()
    })

    socket.on('end', () => {
      this.#logger.log('TACACS+ client disconnected')
    })

    socket.on('close', () => {
      this.#logger.log('TACACS+ client disconnected')
    })

    socket.on('timeout', () => {
      this.#logger.error('TACACS+ client connection timed out')
      socket.destroy()
    })

    return socket
  }

  static readonly DEFAULT_OPTIONS: Options = {
    host: '127.0.0.1',
    port: 49,
    secret: null,
    majorVersion: MAJOR_VERSIONS.TAC_PLUS_MAJOR_VER,
    minorVersion: MINOR_VERSIONS.TAC_PLUS_MINOR_VER_DEFAULT,
    logger: {
      // TODO(lwvemike): remove before release
      /* eslint-disable-next-line no-console */
      log: console.log,
      // TODO(lwvemike): remove before release
      /* eslint-disable-next-line no-console */
      debug: console.debug,
      error: console.error,
    },
  }
}
